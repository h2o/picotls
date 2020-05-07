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
#include <string.h>
#include <tmmintrin.h>
#include <wmmintrin.h>
#include "picotls.h"
#include "picotls/fusion.h"

static const uint64_t poly_[2] __attribute__((aligned(16))) = {1, 0xc200000000000000};
#define poly (*(__m128i *)poly_)
static const uint8_t bswap8_[16] __attribute__((aligned(16))) = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
#define bswap8 (*(__m128i *)bswap8_)
static const uint8_t bswap64_[16] __attribute__((aligned(16))) = {7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8};
#define bswap64 (*(__m128i *)bswap64_)
static const uint8_t one64_[16] __attribute__((aligned(16))) = {0, 0, 0, 0, 0, 0, 0, 0, 1};
#define one64 (*(__m128i *)one64_)

// This function is covered by the Apache License and the MIT License. See Above.
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

static __m128i ghashn(ptls_fusion_aesgcm_context_t *ctx, const __m128i *src, size_t cnt, __m128i ghash)
{
    __m128i hi = _mm_setzero_si128(), lo = _mm_setzero_si128(), mid = _mm_setzero_si128();
    assert(cnt <= 6);

    for (size_t i = 0; i < cnt; ++i) {
        __m128i X = _mm_loadu_si128(src + cnt - 1 - i);
        X = _mm_shuffle_epi8(X, bswap8);
        if (i == cnt - 1)
            X = _mm_xor_si128(X, ghash);
        __m128i t = _mm_clmulepi64_si128(ctx->ghash[i].H, X, 0x00);
        lo = _mm_xor_si128(lo, t);
        t = _mm_clmulepi64_si128(ctx->ghash[i].H, X, 0x11);
        hi = _mm_xor_si128(hi, t);
        t = _mm_shuffle_epi32(X, 78);
        t = _mm_xor_si128(t, X);
        t = _mm_clmulepi64_si128(ctx->ghash[i].r, t, 0x00);
        mid = _mm_xor_si128(mid, t);
    }

    mid = _mm_xor_si128(mid, hi);
    mid = _mm_xor_si128(mid, lo);
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* from https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */
    __m128i r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    ghash = _mm_xor_si128(hi, lo);

    return ghash;
}

static inline __m128i loadn(const void *_p, size_t l)
{
    const uint8_t *p = _p;
    uint8_t buf[16] = {};

    for (size_t i = 0; i != l; ++i)
        buf[i] = p[i];
    return *(__m128i *)buf;
}

static inline void storen(void *_p, size_t l, __m128i v)
{
    uint8_t buf[16], *p = _p;

    *(__m128i *)buf = v;

    for (size_t i = 0; i != l; ++i)
        p[i] = buf[i];
}

void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, const void *iv, const void *_aad, size_t aadlen, void *_dst,
                                const void *_src, size_t srclen)
{
/* init the bits (we can always run in full), but use the last slot for calculating ek0, if possible */
#define AESECB6_INIT()                                                                                                             \
    do {                                                                                                                           \
        ctr = _mm_add_epi64(ctr, one64);                                                                                           \
        bits0 = _mm_shuffle_epi8(ctr, bswap64);                                                                                    \
        ctr = _mm_add_epi64(ctr, one64);                                                                                           \
        bits1 = _mm_shuffle_epi8(ctr, bswap64);                                                                                    \
        ctr = _mm_add_epi64(ctr, one64);                                                                                           \
        bits2 = _mm_shuffle_epi8(ctr, bswap64);                                                                                    \
        ctr = _mm_add_epi64(ctr, one64);                                                                                           \
        bits3 = _mm_shuffle_epi8(ctr, bswap64);                                                                                    \
        ctr = _mm_add_epi64(ctr, one64);                                                                                           \
        bits4 = _mm_shuffle_epi8(ctr, bswap64);                                                                                    \
        if (PTLS_LIKELY(srclen > 16 * 5)) {                                                                                        \
            ctr = _mm_add_epi64(ctr, one64);                                                                                       \
            bits5 = _mm_shuffle_epi8(ctr, bswap64);                                                                                \
        } else if ((state & STATE_EK0_BEEN_FED) == 0) {                                                                            \
            bits5 = ek0;                                                                                                           \
            state |= STATE_EK0_BEEN_FED;                                                                                           \
        }                                                                                                                          \
        __m128i k = ctx->keys[0];                                                                                                  \
        bits0 = _mm_xor_si128(bits0, k);                                                                                           \
        bits1 = _mm_xor_si128(bits1, k);                                                                                           \
        bits2 = _mm_xor_si128(bits2, k);                                                                                           \
        bits3 = _mm_xor_si128(bits3, k);                                                                                           \
        bits4 = _mm_xor_si128(bits4, k);                                                                                           \
        bits5 = _mm_xor_si128(bits5, k);                                                                                           \
    } while (0)

/* aes block update */
#define AESECB6_UPDATE(i)                                                                                                          \
    do {                                                                                                                           \
        __m128i k = ctx->keys[i];                                                                                                  \
        bits0 = _mm_aesenc_si128(bits0, k);                                                                                        \
        bits1 = _mm_aesenc_si128(bits1, k);                                                                                        \
        bits2 = _mm_aesenc_si128(bits2, k);                                                                                        \
        bits3 = _mm_aesenc_si128(bits3, k);                                                                                        \
        bits4 = _mm_aesenc_si128(bits4, k);                                                                                        \
        bits5 = _mm_aesenc_si128(bits5, k);                                                                                        \
    } while (0)

/* aesenclast */
#define AESECB6_FINAL()                                                                                                            \
    do {                                                                                                                           \
        __m128i k = ctx->keys[10];                                                                                                 \
        bits0 = _mm_aesenclast_si128(bits0, k);                                                                                    \
        bits1 = _mm_aesenclast_si128(bits1, k);                                                                                    \
        bits2 = _mm_aesenclast_si128(bits2, k);                                                                                    \
        bits3 = _mm_aesenclast_si128(bits3, k);                                                                                    \
        bits4 = _mm_aesenclast_si128(bits4, k);                                                                                    \
        bits5 = _mm_aesenclast_si128(bits5, k);                                                                                    \
    } while (0)

    __m128i ctr, ek0, bits0, bits1, bits2, bits3, bits4, bits5 = _mm_setzero_si128();
    __m128i hi = _mm_setzero_si128(), lo = _mm_setzero_si128(), mid = _mm_setzero_si128(), gdatabuf[6];
    __m128i ac = _mm_shuffle_epi8(_mm_set_epi32(0, (int)srclen * 8, 0, (int)aadlen * 8), bswap64);

    // src and dst are updated after the chunk is processed
    const __m128i *src = _src;
    __m128i *dst = _dst;
    // aad and src_ghash are updated before the chunk is processed (i.e., when the pointers are fed indo the processor)
    const __m128i *aad = _aad, *dst_ghash = dst;
    size_t dst_ghashlen = srclen;

    struct ptls_fusion_aesgcm_ghash_precompute *ghash_precompute = ctx->ghash + (aadlen + 15) / 16 + (srclen + 15) / 16 + 1;

    int32_t state = 0;
#define STATE_FINAL 0x80000000 /* negates the state when set */
#define STATE_EK0_BEEN_FED 0x3
#define STATE_EK0_INCOMPLETE 0x2
#define STATE_EK0_READY() ((state & STATE_EK0_BEEN_FED) == 0x1)

    /* build counter */
    ctr = loadn(iv, PTLS_AESGCM_IV_SIZE);
    ctr = _mm_shuffle_epi8(ctr, bswap8);
    ctr = _mm_add_epi64(ctr, one64);
    ek0 = _mm_shuffle_epi8(ctr, bswap64);

    /* prepare the first bit stream */
    AESECB6_INIT();
    for (size_t i = 1; i < 10; ++i)
        AESECB6_UPDATE(i);
    AESECB6_FINAL();

    /* the main loop */
    do {
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
            if (srclen != 0) {
#define APPLY(i)                                                                                                                   \
    do {                                                                                                                           \
        if (srclen >= 16) {                                                                                                        \
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src++), bits##i));                                               \
            srclen -= 16;                                                                                                          \
        } else {                                                                                                                   \
            if (srclen != 0) {                                                                                                     \
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
        const __m128i *gdata;
        size_t gdata_cnt;
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
                    if (gdata_cnt < 6) {
                        gdatabuf[gdata_cnt++] = ac;
                        state |= STATE_FINAL;
                    }
                    break;
                }
                gdatabuf[gdata_cnt++] = _mm_loadu_si128(dst_ghash++);
                dst_ghashlen -= 16;
            }
            gdata = gdatabuf;
        }

        /* run AES and multiplification in parallel */
        size_t index = 0;
        for (; index < gdata_cnt; ++index) {

            AESECB6_UPDATE(index + 2);

            --ghash_precompute;
            __m128i X = _mm_loadu_si128(gdata + index);
            X = _mm_shuffle_epi8(X, bswap8);
            __m128i t = _mm_clmulepi64_si128(ghash_precompute->H, X, 0x00);
            lo = _mm_xor_si128(lo, t);
            t = _mm_clmulepi64_si128(ghash_precompute->H, X, 0x11);
            hi = _mm_xor_si128(hi, t);
            t = _mm_shuffle_epi32(X, 78);
            t = _mm_xor_si128(t, X);
            t = _mm_clmulepi64_si128(ghash_precompute->r, t, 0x00);
            mid = _mm_xor_si128(mid, t);
        }

        AESECB6_UPDATE(index + 2);

        for (; index + 3 <= 9; ++index)
            AESECB6_UPDATE(index + 3);

        /* finish bit stream generation */
        AESECB6_FINAL();

    } while (state >= 0);

    if (!STATE_EK0_READY()) {
        if ((state & STATE_EK0_INCOMPLETE) != 0) {
            ek0 = bits5;
        } else {
            assert(!"FIXME either finish the AES loop to get the ");
        }
    }

    /* finish multiplification */
    mid = _mm_xor_si128(mid, hi);
    mid = _mm_xor_si128(mid, lo);
    lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));
    hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));

    /* fast reduction, using https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */
    __m128i r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    r = _mm_clmulepi64_si128(lo, poly, 0x10);
    lo = _mm_shuffle_epi32(lo, 78);
    lo = _mm_xor_si128(lo, r);
    __m128i tag = _mm_xor_si128(hi, lo);
    tag = _mm_shuffle_epi8(tag, bswap8);
    tag = _mm_xor_si128(tag, ek0);
    _mm_storeu_si128(dst, tag);
}

static __m128i expand_key(__m128i key, __m128i t)
{
    t = _mm_shuffle_epi32(t, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, t);
}

void ptls_fusion_aesgcm_init(ptls_fusion_aesgcm_context_t *ctx, const void *_userkey)
{
    __m128i userkey = _mm_loadu_si128((__m128i *)_userkey);
    size_t i = 0;

    ctx->keys[i++] = userkey;
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

    ctx->ghash[0].H = ctx->keys[0];
    for (i = 1; i < PTLS_FUSION_AESGCM_ROUNDS; ++i)
        ctx->ghash[0].H = _mm_aesenc_si128(ctx->ghash[0].H, ctx->keys[i]);
    ctx->ghash[0].H = _mm_aesenclast_si128(ctx->ghash[0].H, ctx->keys[PTLS_FUSION_AESGCM_ROUNDS]);
    ctx->ghash[0].H = _mm_shuffle_epi8(ctx->ghash[0].H, bswap8);

    ctx->ghash[0].H = transformH(ctx->ghash[0].H);
    for (int i = 1; i < PTLS_ELEMENTSOF(ctx->ghash); ++i)
        ctx->ghash[i].H = gfmul(ctx->ghash[i - 1].H, ctx->ghash[0].H);
    for (int i = 0; i < PTLS_ELEMENTSOF(ctx->ghash); ++i) {
        __m128i r = _mm_shuffle_epi32(ctx->ghash[i].H, 78);
        r = _mm_xor_si128(r, ctx->ghash[i].H);
        ctx->ghash[i].r = r;
    }
}

void ptls_fusion_aesgcm_dispose(ptls_fusion_aesgcm_context_t *ctx)
{
    ptls_clear_memory(ctx, sizeof(*ctx));
}

struct aesgcm_context {
    ptls_aead_context_t super;
    ptls_fusion_aesgcm_context_t aesgcm;
};

static void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ptls_fusion_aesgcm_dispose(&ctx->aesgcm);
}

static void aead_do_encrypt_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
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

static size_t aead_do_decrypt(ptls_aead_context_t *_ctx, void *_output, const void *input, size_t inlen, const void *iv,
                              const void *aad, size_t aadlen)
{
    assert(!"FIXME");
    return SIZE_MAX;
}

static int aes128gcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key)
{
    struct aesgcm_context *ctx = (struct aesgcm_context *)_ctx;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = aead_do_encrypt_init;
        ctx->super.do_encrypt_update = aead_do_encrypt_update;
        ctx->super.do_encrypt_final = aead_do_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aead_do_decrypt;
    }

    assert(is_enc);
    ptls_fusion_aesgcm_init(&ctx->aesgcm, key);

    return 0;
}

ptls_aead_algorithm_t ptls_fusion_aes128gcm = {"AES128-GCM",
                                               NULL, // &ptls_fusion_aes128ctr,
                                               NULL, // &ptls_fusion_aes128ecb,
                                               PTLS_AES128_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct aesgcm_context),
                                               aes128gcm_setup_crypto};
