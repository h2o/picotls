/*
 * This source file is licensed under the Apache License 2.0 *and* the MIT
 * License. Please agree to *both* of the licensing terms!
 *
 *
 * `transformH` function is a derivative work of OpenSSL. The original work
 * is covered by the following license:
 *
 * Copyright 2013-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 *
 * All other work, including modifications to the `transformH` function is
 * covered by the following MIT license:
 *
 * Copyright (c) 2020 Fastly, Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <tmmintrin.h>
#include <nmmintrin.h>
#include <wmmintrin.h>
#include "picotls.h"
#include "picotls/fusion.h"

struct ptls_fusion_aesgcm_context {
    ptls_fusion_aesecb_context_t ecb;
    size_t ghash_cnt;
    struct ptls_fusion_aesgcm_ghash_precompute {
        __m128i H;
        __m128i r;
    } ghash[0];
};

struct ctr_context {
    ptls_cipher_context_t super;
    ptls_fusion_aesecb_context_t fusion;
    __m128i bits;
    uint8_t is_ready;
};

struct aesgcm_context {
    ptls_aead_context_t super;
    ptls_fusion_aesgcm_context_t *aesgcm;
    /**
     * retains the static IV in the upper 96 bits (in little endian)
     */
    __m128i static_iv;
};

static const uint64_t poly_[2] __attribute__((aligned(16))) = {1, 0xc200000000000000};
#define poly (*(__m128i *)poly_)
static const uint8_t bswap8_[16] __attribute__((aligned(16))) = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
#define bswap8 (*(__m128i *)bswap8_)
static const uint8_t one8_[16] __attribute__((aligned(16))) = {1};
#define one8 (*(__m128i *)one8_)

/* This function is covered by the Apache License and the MIT License. The origin is crypto/modes/asm/ghash-x86_64.pl of openssl
 * at commit 33388b4. */
static __m128i transformH(__m128i H)
{
    //  # <<1 twist
    //  pshufd          \$0b11111111,$Hkey,$T2  # broadcast uppermost dword
    __m128i t2 = _mm_shuffle_epi32(H, 0xff);
    // movdqa          $Hkey,$T1
    __m128i t1 = H;
    // psllq           \$1,$Hkey
    H = _mm_slli_epi64(H, 1);
    // pxor            $T3,$T3                 #
    __m128i t3 = _mm_setzero_si128();
    // psrlq           \$63,$T1
    t1 = _mm_srli_epi64(t1, 63);
    // pcmpgtd         $T2,$T3                 # broadcast carry bit
    t3 = _mm_cmplt_epi32(t2, t3);
    //     pslldq          \$8,$T1
    t1 = _mm_slli_si128(t1, 8);
    // por             $T1,$Hkey               # H<<=1
    H = _mm_or_si128(t1, H);

    // # magic reduction
    // pand            .L0x1c2_polynomial(%rip),$T3
    t3 = _mm_and_si128(t3, poly);
    // pxor            $T3,$Hkey               # if(carry) H^=0x1c2_polynomial
    H = _mm_xor_si128(t3, H);

    return H;
}
// end of Apache License code

static __m128i gfmul(__m128i x, __m128i y)
{
    __m128i lo = _mm_clmulepi64_si128(x, y, 0x00);
    __m128i hi = _mm_clmulepi64_si128(x, y, 0x11);

    __m128i a = _mm_shuffle_epi32(x, 78);
    __m128i b = _mm_shuffle_epi32(y, 78);
    a = _mm_xor_si128(a, x);
    b = _mm_xor_si128(b, y);

    a = _mm_clmulepi64_si128(a, b, 0x00);
    a = _mm_xor_si128(a, lo);
    a = _mm_xor_si128(a, hi);

    b = _mm_slli_si128(a, 8);
    a = _mm_srli_si128(a, 8);

    lo = _mm_xor_si128(lo, b);
    hi = _mm_xor_si128(hi, a);

    // from https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf
    __m128i t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, t);
    t = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, t);

    return _mm_xor_si128(hi, lo);
}

struct ptls_fusion_gfmul_state {
    __m128i hi, lo, mid;
};

static inline void gfmul_onestep(struct ptls_fusion_gfmul_state *gstate, __m128i X,
                                 struct ptls_fusion_aesgcm_ghash_precompute *precompute)
{
    X = _mm_shuffle_epi8(X, bswap8);
    __m128i t = _mm_clmulepi64_si128(precompute->H, X, 0x00);
    gstate->lo = _mm_xor_si128(gstate->lo, t);
    t = _mm_clmulepi64_si128(precompute->H, X, 0x11);
    gstate->hi = _mm_xor_si128(gstate->hi, t);
    t = _mm_shuffle_epi32(X, 78);
    t = _mm_xor_si128(t, X);
    t = _mm_clmulepi64_si128(precompute->r, t, 0x00);
    gstate->mid = _mm_xor_si128(gstate->mid, t);
}

static inline __m128i gfmul_final(struct ptls_fusion_gfmul_state *gstate, __m128i ek0)
{
    /* finish multiplication */
    gstate->mid = _mm_xor_si128(gstate->mid, gstate->hi);
    gstate->mid = _mm_xor_si128(gstate->mid, gstate->lo);
    gstate->lo = _mm_xor_si128(gstate->lo, _mm_slli_si128(gstate->mid, 8));
    gstate->hi = _mm_xor_si128(gstate->hi, _mm_srli_si128(gstate->mid, 8));

    /* fast reduction, using https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */
    __m128i r = _mm_clmulepi64_si128(gstate->lo, poly, 0x10);
    gstate->lo = _mm_shuffle_epi32(gstate->lo, 78);
    gstate->lo = _mm_xor_si128(gstate->lo, r);
    r = _mm_clmulepi64_si128(gstate->lo, poly, 0x10);
    gstate->lo = _mm_shuffle_epi32(gstate->lo, 78);
    gstate->lo = _mm_xor_si128(gstate->lo, r);
    __m128i tag = _mm_xor_si128(gstate->hi, gstate->lo);
    tag = _mm_shuffle_epi8(tag, bswap8);
    tag = _mm_xor_si128(tag, ek0);

    return tag;
}

static inline __m128i aesecb_encrypt(ptls_fusion_aesecb_context_t *ctx, __m128i v)
{
    size_t i;

    v = _mm_xor_si128(v, ctx->keys[0]);
    for (i = 1; i < PTLS_FUSION_AES_ROUNDS; ++i)
        v = _mm_aesenc_si128(v, ctx->keys[i]);
    v = _mm_aesenclast_si128(v, ctx->keys[i]);

    return v;
}

static inline __m128i loadn(const void *_p, size_t l)
{
    /* FIXME is this optimal? */
    if (PTLS_LIKELY(((uintptr_t)_p % 4096) <= 4080)) {
        static const uint8_t mask[31] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        return _mm_and_si128(_mm_loadu_si128(_p), _mm_loadu_si128((__m128i *)(mask + 16 - l)));
    } else {
        const uint8_t *p = _p;
        uint8_t buf[16] = {};
        for (size_t i = 0; i != l; ++i)
            buf[i] = p[i];
        return *(__m128i *)buf;
    }
}

static inline void storen(void *_p, size_t l, __m128i v)
{
    uint8_t buf[16], *p = _p;

    *(__m128i *)buf = v;

    for (size_t i = 0; i != l; ++i)
        p[i] = buf[i];
}

void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                                const void *_aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits0 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits1 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits2 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits3 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits4 = _mm_shuffle_epi8(ctr, bswap8);                                                                                     \
        if (PTLS_LIKELY(srclen > 16 * 5)) {                                                                                        \
            ctr = _mm_add_epi64(ctr, one8);                                                                                        \
            bits5 = _mm_shuffle_epi8(ctr, bswap8);                                                                                 \
        } else {                                                                                                                   \
            if ((state & STATE_EK0_BEEN_FED) == 0) {                                                                               \
                bits5 = ek0;                                                                                                       \
                state |= STATE_EK0_BEEN_FED;                                                                                       \
            }                                                                                                                      \
            if ((state & STATE_SUPP_USED) != 0 && srclen <= 16 * 4 && (const __m128i *)supp->input + 1 <= dst_ghash) {             \
                bits4 = _mm_loadu_si128(supp->input);                                                                              \
                bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys;                                                        \
                state |= STATE_SUPP_IN_PROCESS;                                                                                    \
            }                                                                                                                      \
        }                                                                                                                          \
        __m128i k = ctx->ecb.keys[0];                                                                                              \
        bits0 = _mm_xor_si128(bits0, k);                                                                                           \
        bits1 = _mm_xor_si128(bits1, k);                                                                                           \
        bits2 = _mm_xor_si128(bits2, k);                                                                                           \
        bits3 = _mm_xor_si128(bits3, k);                                                                                           \
        bits4 = _mm_xor_si128(bits4, bits4keys[0]);                                                                                \
        bits5 = _mm_xor_si128(bits5, k);                                                                                           \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->ecb.keys[i];                                                                                              \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, bits4keys[i]);                                                                             \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL()                                                                                                            \
    do {                                                                                                                           \
        __m128i k = ctx->ecb.keys[10];                                                                                             \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, bits4keys[10]);                                                                        \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    __m128i ek0, bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    const __m128i *bits4keys = ctx->ecb.keys; /* is changed to supp->ctx.keys when calcurating suppout */
    struct ptls_fusion_gfmul_state gstate = {};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), bswap8);

    const __m128i *gdata; // points to the elements fed into GHASH
    size_t gdata_cnt;

    // src and dst are updated after the chunk is processed
    const __m128i *src = input;
    __m128i *dst = output;
    size_t srclen = inlen;
    // aad and src_ghash are updated before the chunk is processed (i.e., when the pointers are fed indo the processor)
    const __m128i *aad = _aad, *dst_ghash = dst;
    size_t dst_ghashlen = srclen;

    struct ptls_fusion_aesgcm_ghash_precompute *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (srclen + 15) / 16 + 1;

#define STATE_EK0_BEEN_FED 0x3
#define STATE_EK0_INCOMPLETE 0x2
#define STATE_EK0_READY() ((state & STATE_EK0_BEEN_FED) == 0x1)
#define STATE_SUPP_USED 0x4
#define STATE_SUPP_IN_PROCESS 0x8
    int32_t state = supp != NULL ? STATE_SUPP_USED : 0;

    /* build counter */
    ctr = _mm_insert_epi32(ctr, 1, 0);
    ek0 = _mm_shuffle_epi8(ctr, bswap8);

    /* prepare the first bit stream */
    AESECB6_INIT();
    for (size_t i = 1; i < 10; ++i)
        AESECB6_UPDATE(i);
    AESECB6_FINAL();

    /* the main loop */
    while (1) {
        /* apply the bit stream to src and write to dest */
        if (PTLS_LIKELY(srclen >= 6 * 16)) {
#define APPLY(i) _mm_storeu_si128(dst + i, _mm_xor_si128(_mm_loadu_si128(src + i), bits##i))
            APPLY(0);
            APPLY(1);
            APPLY(2);
            APPLY(3);
            APPLY(4);
            APPLY(5);
#undef APPLY
            dst += 6;
            src += 6;
            srclen -= 6 * 16;
        } else {
            if ((state & STATE_EK0_BEEN_FED) == STATE_EK0_BEEN_FED) {
                ek0 = bits5;
                state &= ~STATE_EK0_INCOMPLETE;
            }
            if ((state & STATE_SUPP_IN_PROCESS) != 0) {
                _mm_storeu_si128((__m128i *)supp->output, bits4);
                state &= ~(STATE_SUPP_USED | STATE_SUPP_IN_PROCESS);
            }
            if (srclen != 0) {
#define APPLY(i)                                                                                                                   \
    do {                                                                                                                           \
        if (srclen >= 16) {                                                                                                        \
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src++), bits##i));                                               \
            srclen -= 16;                                                                                                          \
        } else {                                                                                                                   \
            if (srclen != 0) {                                                                                                     \
                /* While it is possible to use _mm_storeu_si128 here, as there is space to store GCM tag, writing byte-per-byte    \
                 * seems to be faster on 9th gen Core. */                                                                          \
                storen(dst, srclen, _mm_xor_si128(loadn(src, srclen), bits##i));                                                   \
                dst = (__m128i *)((uint8_t *)dst + srclen);                                                                        \
                srclen = 0;                                                                                                        \
            }                                                                                                                      \
            goto ApplyEnd;                                                                                                         \
        }                                                                                                                          \
    } while (0)
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
            ApplyEnd:;
#undef APPLY
            }
        }

        /* next block AES starts here */
        AESECB6_INIT();

        AESECB6_UPDATE(1);

        /* setup gdata */
        if (PTLS_UNLIKELY(aadlen != 0)) {
            gdata_cnt = 0;
            while (gdata_cnt < 6) {
                if (aadlen < 16) {
                    if (aadlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn(aad, aadlen);
                        aadlen = 0;
                    }
                    goto GdataFillDST;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
            }
            gdata = gdatabuf;
        } else if (PTLS_LIKELY(dst_ghashlen >= 6 * 16)) {
            gdata = dst_ghash;
            gdata_cnt = 6;
            dst_ghash += 6;
            dst_ghashlen -= 96;
        } else {
            gdata_cnt = 0;
        GdataFillDST:
            while (gdata_cnt < 6) {
                if (dst_ghashlen < 16) {
                    if (dst_ghashlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn(dst_ghash, dst_ghashlen);
                        dst_ghashlen = 0;
                    }
                    if (gdata_cnt < 6)
                        goto Finish;
                    break;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(dst_ghash++);
                dst_ghashlen -= 16;
            }
            gdata = gdatabuf;
        }

        /* run AES and multiplication in parallel */
        for (size_t i = 2; i <= 7; ++i) {
            AESECB6_UPDATE(i);
            gfmul_onestep(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
        }
        AESECB6_UPDATE(8);
        AESECB6_UPDATE(9);
        AESECB6_FINAL();
    }

Finish:
    gdatabuf[gdata_cnt++] = ac;

    /* We have complete set of data to be fed into GHASH. Let's finish the remaining calculation.
     * Note that by now, all AES operations for payload encryption and ek0 are complete. This is is because it is necessary for GCM
     * to process at least the same amount of data (i.e. payload-blocks + AC), and because AES is at least one 96-byte block ahead.
     */
    assert(STATE_EK0_READY());
    for (size_t i = 0; i < gdata_cnt; ++i)
        gfmul_onestep(&gstate, gdatabuf[i], --ghash_precompute);

    _mm_storeu_si128(dst, gfmul_final(&gstate, ek0));

    /* Finish the calculation of supplemental vector. Done at the very last, because the sample might cover the GCM tag. */
    if ((state & STATE_SUPP_USED) != 0) {
        size_t i;
        if ((state & STATE_SUPP_IN_PROCESS) == 0) {
            bits4keys = ((struct ctr_context *)supp->ctx)->fusion.keys;
            bits4 = _mm_xor_si128(_mm_loadu_si128(supp->input), bits4keys[0]);
            i = 1;
        } else {
            i = 2;
        }
        do {
            bits4 = _mm_aesenc_si128(bits4, bits4keys[i++]);
        } while (i != 10);
        bits4 = _mm_aesenclast_si128(bits4, bits4keys[10]);
        _mm_storeu_si128((__m128i *)supp->output, bits4);
    }

#undef AESECB6_INIT
#undef AESECB6_UPDATE
#undef AESECB6_FINAL
#undef STATE_EK0_BEEN_FOUND
#undef STATE_EK0_READY
#undef STATE_SUPP_IN_PROCESS
}

int ptls_fusion_aesgcm_decrypt(ptls_fusion_aesgcm_context_t *ctx, void *output, const void *input, size_t inlen, __m128i ctr,
                               const void *_aad, size_t aadlen, const void *tag)
{
    __m128i ek0 = _mm_setzero_si128(), bits0, bits1 = _mm_setzero_si128(), bits2 = _mm_setzero_si128(), bits3 = _mm_setzero_si128(),
            bits4 = _mm_setzero_si128(), bits5 = _mm_setzero_si128();
    struct ptls_fusion_gfmul_state gstate = {};
    __m128i gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)aadlen * 8, 0, (int)inlen * 8), bswap8);
    struct ptls_fusion_aesgcm_ghash_precompute *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (inlen + 15) / 16 + 1;

    const __m128i *gdata; // points to the elements fed into GHASH
    size_t gdata_cnt;

    const __m128i *src_ghash = input, *src_aes = input, *aad = _aad;
    __m128i *dst = output;
    size_t nondata_aes_cnt = 0, src_ghashlen = inlen, src_aeslen = inlen;

    /* schedule ek0 and suppkey */
    ctr = _mm_add_epi64(ctr, one8);
    bits0 = _mm_xor_si128(_mm_shuffle_epi8(ctr, bswap8), ctx->ecb.keys[0]);
    ++nondata_aes_cnt;

#define STATE_IS_FIRST_RUN 0x1
#define STATE_GHASH_HAS_MORE 0x2
    int state = STATE_IS_FIRST_RUN | STATE_GHASH_HAS_MORE;

    /* the main loop */
    while (1) {

        /* setup gdata */
        if (PTLS_UNLIKELY(aadlen != 0)) {
            gdata = gdatabuf;
            gdata_cnt = 0;
            while (gdata_cnt < 6) {
                if (aadlen < 16) {
                    if (aadlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn(aad, aadlen);
                        aadlen = 0;
                        ++nondata_aes_cnt;
                    }
                    goto GdataFillSrc;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
                ++nondata_aes_cnt;
            }
        } else if (PTLS_LIKELY(src_ghashlen >= 6 * 16)) {
            gdata = src_ghash;
            gdata_cnt = 6;
            src_ghash += 6;
            src_ghashlen -= 6 * 16;
        } else {
            gdata = gdatabuf;
            gdata_cnt = 0;
        GdataFillSrc:
            while (gdata_cnt < 6) {
                if (src_ghashlen < 16) {
                    if (src_ghashlen != 0) {
                        gdatabuf[gdata_cnt++] = loadn(src_ghash, src_ghashlen);
                        src_ghash = (__m128i *)((uint8_t *)src_ghash + src_ghashlen);
                        src_ghashlen = 0;
                    }
                    if (gdata_cnt < 6 && (state & STATE_GHASH_HAS_MORE) != 0) {
                        gdatabuf[gdata_cnt++] = ac;
                        state &= ~STATE_GHASH_HAS_MORE;
                    }
                    break;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(src_ghash++);
                src_ghashlen -= 16;
            }
        }

        /* setup aes bits */
        if (PTLS_LIKELY(nondata_aes_cnt == 0))
            goto InitAllBits;
        switch (nondata_aes_cnt) {
#define INIT_BITS(n, keys)                                                                                                         \
    case n:                                                                                                                        \
        ctr = _mm_add_epi64(ctr, one8);                                                                                            \
        bits##n = _mm_xor_si128(_mm_shuffle_epi8(ctr, bswap8), keys[0]);
        InitAllBits:
            INIT_BITS(0, ctx->ecb.keys);
            INIT_BITS(1, ctx->ecb.keys);
            INIT_BITS(2, ctx->ecb.keys);
            INIT_BITS(3, ctx->ecb.keys);
            INIT_BITS(4, ctx->ecb.keys);
            INIT_BITS(5, ctx->ecb.keys);
#undef INIT_BITS
        }

        { /* run aes and ghash */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->ecb.keys[i];                                                                                              \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, k);                                                                                        \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

            size_t aesi;
            for (aesi = 1; aesi <= gdata_cnt; ++aesi) {
                AESECB6_UPDATE(aesi);
                gfmul_onestep(&gstate, _mm_loadu_si128(gdata++), --ghash_precompute);
            }
            for (; aesi <= 9; ++aesi)
                AESECB6_UPDATE(aesi);
            __m128i k = ctx->ecb.keys[aesi];
            bits0 = _mm_aesenclast_si128(bits0, k);
            bits1 = _mm_aesenclast_si128(bits1, k);
            bits2 = _mm_aesenclast_si128(bits2, k);
            bits3 = _mm_aesenclast_si128(bits3, k);
            bits4 = _mm_aesenclast_si128(bits4, k);
            bits5 = _mm_aesenclast_si128(bits5, k);

#undef AESECB6_UPDATE
        }

        /* apply aes bits */
        if (PTLS_LIKELY(nondata_aes_cnt == 0 && src_aeslen >= 6 * 16)) {
#define APPLY(i) _mm_storeu_si128(dst + i, _mm_xor_si128(_mm_loadu_si128(src_aes + i), bits##i))
            APPLY(0);
            APPLY(1);
            APPLY(2);
            APPLY(3);
            APPLY(4);
            APPLY(5);
#undef APPLY
            dst += 6;
            src_aes += 6;
            src_aeslen -= 6 * 16;
        } else {
            if ((state & STATE_IS_FIRST_RUN) != 0) {
                ek0 = bits0;
                state &= ~STATE_IS_FIRST_RUN;
            }
            switch (nondata_aes_cnt) {
#define APPLY(i)                                                                                                                   \
    case i:                                                                                                                        \
        if (PTLS_LIKELY(src_aeslen > 16)) {                                                                                        \
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src_aes++), bits##i));                                           \
            src_aeslen -= 16;                                                                                                      \
        } else {                                                                                                                   \
            if (src_aeslen == 16) {                                                                                                \
                _mm_storeu_si128(dst, _mm_xor_si128(_mm_loadu_si128(src_aes), bits##i));                                           \
            } else if (src_aeslen != 0) {                                                                                          \
                storen(dst, src_aeslen, _mm_xor_si128(loadn(src_aes, src_aeslen), bits##i));                                       \
            }                                                                                                                      \
            src_aeslen = 0;                                                                                                        \
            goto Finish;                                                                                                           \
        }
                APPLY(0);
                APPLY(1);
                APPLY(2);
                APPLY(3);
                APPLY(4);
                APPLY(5);
#undef APPLY
            }
            nondata_aes_cnt = 0;
        }
    }

Finish:
    assert((state & STATE_IS_FIRST_RUN) == 0);

    /* the only case where AES operation is complete and GHASH is not is when the application of AC is remaining */
    if ((state & STATE_GHASH_HAS_MORE) != 0) {
        assert(ghash_precompute - 1 == ctx->ghash);
        gfmul_onestep(&gstate, ac, --ghash_precompute);
    }

    __m128i calctag = gfmul_final(&gstate, ek0);

    return _mm_movemask_epi8(_mm_cmpeq_epi8(calctag, _mm_loadu_si128(tag))) == 0xffff;

#undef STATE_IS_FIRST_RUN
#undef STATE_GHASH_HAS_MORE
}

static __m128i expand_key(__m128i key, __m128i t)
{
    t = _mm_shuffle_epi32(t, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, t);
}

void ptls_fusion_aesecb_init(ptls_fusion_aesecb_context_t *ctx, const void *key)
{
    size_t i = 0;

    ctx->keys[i++] = _mm_loadu_si128((__m128i *)key);
#define EXPAND(R)                                                                                                                  \
    do {                                                                                                                           \
        ctx->keys[i] = expand_key(ctx->keys[i - 1], _mm_aeskeygenassist_si128(ctx->keys[i - 1], R));                               \
        ++i;                                                                                                                       \
    } while (0)
    EXPAND(0x1);
    EXPAND(0x2);
    EXPAND(0x4);
    EXPAND(0x8);
    EXPAND(0x10);
    EXPAND(0x20);
    EXPAND(0x40);
    EXPAND(0x80);
    EXPAND(0x1b);
    EXPAND(0x36);
#undef EXPAND
}

void ptls_fusion_aesecb_dispose(ptls_fusion_aesecb_context_t *ctx)
{
    ptls_clear_memory(ctx, sizeof(*ctx));
}

ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_create(const void *key, size_t max_size)
{
    ptls_fusion_aesgcm_context_t *ctx;
    size_t ghash_cnt = (max_size + 15) / 16 + 2; // round-up by block size, add to handle worst split of the size between AAD and
                                                 // payload, plus context to hash AC

    if ((ctx = malloc(sizeof(*ctx) + sizeof(ctx->ghash[0]) * ghash_cnt)) == NULL)
        return NULL;

    ptls_fusion_aesecb_init(&ctx->ecb, key);

    ctx->ghash_cnt = ghash_cnt;
    ctx->ghash[0].H = aesecb_encrypt(&ctx->ecb, _mm_setzero_si128());
    ctx->ghash[0].H = _mm_shuffle_epi8(ctx->ghash[0].H, bswap8);

    ctx->ghash[0].H = transformH(ctx->ghash[0].H);
    for (int i = 1; i < ghash_cnt; ++i)
        ctx->ghash[i].H = gfmul(ctx->ghash[i - 1].H, ctx->ghash[0].H);
    for (int i = 0; i < ghash_cnt; ++i) {
        __m128i r = _mm_shuffle_epi32(ctx->ghash[i].H, 78);
        r = _mm_xor_si128(r, ctx->ghash[i].H);
        ctx->ghash[i].r = r;
    }

    return ctx;
}

void ptls_fusion_aesgcm_destroy(ptls_fusion_aesgcm_context_t *ctx)
{
    ptls_clear_memory(ctx->ghash, sizeof(ctx->ghash[0]) * ctx->ghash_cnt);
    ctx->ghash_cnt = 0;
    ptls_fusion_aesecb_dispose(&ctx->ecb);
    free(ctx);
}

static void ctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;
    ptls_fusion_aesecb_dispose(&ctx->fusion);
    _mm_storeu_si128(&ctx->bits, _mm_setzero_si128());
}

static void ctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;
    _mm_storeu_si128(&ctx->bits, aesecb_encrypt(&ctx->fusion, _mm_loadu_si128(iv)));
    ctx->is_ready = 1;
}

static void ctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;

    assert((ctx->is_ready && len <= 16) ||
           !"CTR transfomation is supported only once per call to `init` and the maximum size is limited  to 16 bytes");
    ctx->is_ready = 0;

    if (len < 16) {
        storen(output, len, _mm_xor_si128(_mm_loadu_si128(&ctx->bits), loadn(input, len)));
    } else {
        _mm_storeu_si128(output, _mm_xor_si128(_mm_loadu_si128(&ctx->bits), _mm_loadu_si128(input)));
    }
}

static int aes128ctr_setup(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct ctr_context *ctx = (struct ctr_context *)_ctx;

    ctx->super.do_dispose = ctr_dispose;
    ctx->super.do_init = ctr_init;
    ctx->super.do_transform = ctr_transform;
    ptls_fusion_aesecb_init(&ctx->fusion, key);
    ctx->is_ready = 0;

    return 0;
}

static void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ptls_fusion_aesgcm_destroy(ctx->aesgcm);
}

static void aead_do_encrypt_init(ptls_aead_context_t *_ctx, uint64_t seq, const void *aad, size_t aadlen)
{
    assert(!"FIXME");
}

static size_t aead_do_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    assert(!"FIXME");
    return SIZE_MAX;
}

static size_t aead_do_encrypt_final(ptls_aead_context_t *_ctx, void *_output)
{
    assert(!"FIXME");
    return SIZE_MAX;
}

static inline __m128i calc_counter(struct aesgcm_context *ctx, uint64_t seq)
{
    __m128i ctr = _mm_setzero_si128();
    ctr = _mm_insert_epi64(ctr, seq, 0);
    ctr = _mm_slli_si128(ctr, 4);
    ctr = _mm_xor_si128(ctx->static_iv, ctr);
    return ctr;
}

void aead_do_encrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                     const void *aad, size_t aadlen, ptls_aead_supplementary_encryption_t *supp)
{
    struct aesgcm_context *ctx = (void *)_ctx;

    ptls_fusion_aesgcm_encrypt(ctx->aesgcm, output, input, inlen, calc_counter(ctx, seq), aad, aadlen, supp);
}

static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, uint64_t seq,
                              const void *aad, size_t aadlen)
{
    struct aesgcm_context *ctx = (void *)_ctx;

    if (inlen < 16)
        return SIZE_MAX;

    size_t enclen = inlen - 16;
    if (!ptls_fusion_aesgcm_decrypt(ctx->aesgcm, output, input, enclen, calc_counter(ctx, seq), aad, aadlen,
                                    (const uint8_t *)input + enclen))
        return SIZE_MAX;
    return enclen;
}

static int aes128gcm_setup(ptls_aead_context_t *_ctx, int is_enc, const void *key, const void *iv)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ctx->static_iv = loadn(iv, PTLS_AESGCM_IV_SIZE);
    ctx->static_iv = _mm_shuffle_epi8(ctx->static_iv, bswap8);

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    ctx->super.do_encrypt_init = aead_do_encrypt_init;
    ctx->super.do_encrypt_update = aead_do_encrypt_update;
    ctx->super.do_encrypt_final = aead_do_encrypt_final;
    ctx->super.do_encrypt = aead_do_encrypt;
    ctx->super.do_decrypt = aead_do_decrypt;

    ctx->aesgcm = ptls_fusion_aesgcm_create(key, 1500); /* FIXME use realloc with exponential back-off to support arbitrary size */

    return 0;
}

ptls_cipher_algorithm_t ptls_fusion_aes128ctr = {"AES128-CTR",
                                                 PTLS_AES128_KEY_SIZE,
                                                 1, // block size
                                                 PTLS_AES_IV_SIZE,
                                                 sizeof(struct ctr_context),
                                                 aes128ctr_setup};
ptls_aead_algorithm_t ptls_fusion_aes128gcm = {"AES128-GCM",
                                               &ptls_fusion_aes128ctr,
                                               NULL, // &ptls_fusion_aes128ecb,
                                               PTLS_AES128_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct aesgcm_context),
                                               aes128gcm_setup};

int ptls_fusion_is_supported_by_cpu(void)
{
    unsigned leaf1_ecx, leaf7_ebx;

    { /* GCC-specific code to obtain CPU features */
        unsigned leaf_cnt;
        __asm__("cpuid" : "=a"(leaf_cnt) : "a"(0) : "ebx", "ecx", "edx");
        if (leaf_cnt < 7)
            return 0;
        __asm__("cpuid" : "=c"(leaf1_ecx) : "a"(1) : "ebx", "edx");
        __asm__("cpuid" : "=b"(leaf7_ebx) : "a"(7), "c"(0) : "edx");
    }

    /* AVX2 */
    if ((leaf7_ebx & (1 << 5)) == 0)
        return 0;
    /* AES */
    if ((leaf1_ecx & (1 << 25)) == 0)
        return 0;
    /* PCLMUL */
    if ((leaf1_ecx & (1 << 1)) == 0)
        return 0;

    return 1;
}
