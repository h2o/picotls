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

#define AESECB6(b1, b2, b3, b4, b5, b6, b7, b8, b9)                                                                                \
    do {                                                                                                                           \
        __m128i aesk = ctx->keys[0];                                                                                               \
        __m128i aes1 = _mm_xor_si128(data[0], aesk);                                                                               \
        __m128i aes2 = _mm_xor_si128(data[1], aesk);                                                                               \
        __m128i aes3 = _mm_xor_si128(data[2], aesk);                                                                               \
        __m128i aes4 = _mm_xor_si128(data[3], aesk);                                                                               \
        __m128i aes5 = _mm_xor_si128(data[4], aesk);                                                                               \
        __m128i aes6 = _mm_xor_si128(data[5], aesk);                                                                               \
        aesk = ctx->keys[1];                                                                                                       \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b1} aesk = ctx->keys[2];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b2} aesk = ctx->keys[3];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b3} aesk = ctx->keys[4];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b4} aesk = ctx->keys[5];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b5} aesk = ctx->keys[6];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b6} aesk = ctx->keys[7];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b7} aesk = ctx->keys[8];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b8} aesk = ctx->keys[9];                                                                                                  \
        aes1 = _mm_aesenc_si128(aes1, aesk);                                                                                       \
        aes2 = _mm_aesenc_si128(aes2, aesk);                                                                                       \
        aes3 = _mm_aesenc_si128(aes3, aesk);                                                                                       \
        aes4 = _mm_aesenc_si128(aes4, aesk);                                                                                       \
        aes5 = _mm_aesenc_si128(aes5, aesk);                                                                                       \
        aes6 = _mm_aesenc_si128(aes6, aesk);                                                                                       \
        {b9} aesk = ctx->keys[10];                                                                                                 \
        data[0] = _mm_aesenclast_si128(aes1, aesk);                                                                                \
        data[1] = _mm_aesenclast_si128(aes2, aesk);                                                                                \
        data[2] = _mm_aesenclast_si128(aes3, aesk);                                                                                \
        data[3] = _mm_aesenclast_si128(aes4, aesk);                                                                                \
        data[4] = _mm_aesenclast_si128(aes5, aesk);                                                                                \
        data[5] = _mm_aesenclast_si128(aes6, aesk);                                                                                \
    } while (0)

static inline void aesecb6(ptls_fusion_aesgcm_context_t *ctx, __m128i *data)
{
    AESECB6({}, {}, {}, {}, {}, {}, {}, {}, {});
}

#define GHASH6(FUNC)                                                                                                               \
    do {                                                                                                                           \
        __m128i X, lo, hi, mid, r, t;                                                                                              \
        FUNC(                                                                                                                      \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 5);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                lo = _mm_clmulepi64_si128(ctx->ghash[0].H, X, 0x00);                                                               \
                hi = _mm_clmulepi64_si128(ctx->ghash[0].H, X, 0x11);                                                               \
                mid = _mm_shuffle_epi32(X, 78);                                                                                    \
                mid = _mm_xor_si128(mid, X);                                                                                       \
                mid = _mm_clmulepi64_si128(ctx->ghash[0].r, mid, 0x00);                                                            \
            },                                                                                                                     \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 4);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                t = _mm_clmulepi64_si128(ctx->ghash[1].H, X, 0x00);                                                                \
                lo = _mm_xor_si128(lo, t);                                                                                         \
                t = _mm_clmulepi64_si128(ctx->ghash[1].H, X, 0x11);                                                                \
                hi = _mm_xor_si128(hi, t);                                                                                         \
                t = _mm_shuffle_epi32(X, 78);                                                                                      \
                t = _mm_xor_si128(t, X);                                                                                           \
                t = _mm_clmulepi64_si128(ctx->ghash[1].r, t, 0x00);                                                                \
                mid = _mm_xor_si128(mid, t);                                                                                       \
            },                                                                                                                     \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 3);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                t = _mm_clmulepi64_si128(ctx->ghash[2].H, X, 0x00);                                                                \
                lo = _mm_xor_si128(lo, t);                                                                                         \
                t = _mm_clmulepi64_si128(ctx->ghash[2].H, X, 0x11);                                                                \
                hi = _mm_xor_si128(hi, t);                                                                                         \
                t = _mm_shuffle_epi32(X, 78);                                                                                      \
                t = _mm_xor_si128(t, X);                                                                                           \
                t = _mm_clmulepi64_si128(ctx->ghash[2].r, t, 0x00);                                                                \
                mid = _mm_xor_si128(mid, t);                                                                                       \
            },                                                                                                                     \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 2);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                t = _mm_clmulepi64_si128(ctx->ghash[3].H, X, 0x00);                                                                \
                lo = _mm_xor_si128(lo, t);                                                                                         \
                t = _mm_clmulepi64_si128(ctx->ghash[3].H, X, 0x11);                                                                \
                hi = _mm_xor_si128(hi, t);                                                                                         \
                t = _mm_shuffle_epi32(X, 78);                                                                                      \
                t = _mm_xor_si128(t, X);                                                                                           \
                t = _mm_clmulepi64_si128(ctx->ghash[3].r, t, 0x00);                                                                \
                mid = _mm_xor_si128(mid, t);                                                                                       \
            },                                                                                                                     \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 1);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                t = _mm_clmulepi64_si128(ctx->ghash[4].H, X, 0x00);                                                                \
                lo = _mm_xor_si128(lo, t);                                                                                         \
                t = _mm_clmulepi64_si128(ctx->ghash[4].H, X, 0x11);                                                                \
                hi = _mm_xor_si128(hi, t);                                                                                         \
                t = _mm_shuffle_epi32(X, 78);                                                                                      \
                t = _mm_xor_si128(t, X);                                                                                           \
                t = _mm_clmulepi64_si128(ctx->ghash[4].r, t, 0x00);                                                                \
                mid = _mm_xor_si128(mid, t);                                                                                       \
            },                                                                                                                     \
            {                                                                                                                      \
                X = _mm_loadu_si128(gdata + 0);                                                                                    \
                X = _mm_shuffle_epi8(X, bswap8);                                                                                   \
                X = _mm_xor_si128(X, ghash);                                                                                       \
                t = _mm_clmulepi64_si128(ctx->ghash[5].H, X, 0x00);                                                                \
                lo = _mm_xor_si128(lo, t);                                                                                         \
                t = _mm_clmulepi64_si128(ctx->ghash[5].H, X, 0x11);                                                                \
            },                                                                                                                     \
            {                                                                                                                      \
                hi = _mm_xor_si128(hi, t);                                                                                         \
                t = _mm_shuffle_epi32(X, 78);                                                                                      \
                t = _mm_xor_si128(t, X);                                                                                           \
                t = _mm_clmulepi64_si128(ctx->ghash[5].r, t, 0x00);                                                                \
                mid = _mm_xor_si128(mid, t);                                                                                       \
            },                                                                                                                     \
            {                                                                                                                      \
                mid = _mm_xor_si128(mid, hi);                                                                                      \
                mid = _mm_xor_si128(mid, lo);                                                                                      \
                lo = _mm_xor_si128(lo, _mm_slli_si128(mid, 8));                                                                    \
                hi = _mm_xor_si128(hi, _mm_srli_si128(mid, 8));                                                                    \
                                                                                                                                   \
                /* from https://crypto.stanford.edu/RealWorldCrypto/slides/gueron.pdf */                                           \
                r = _mm_clmulepi64_si128(lo, poly, 0x10);                                                                          \
            },                                                                                                                     \
            {                                                                                                                      \
                lo = _mm_shuffle_epi32(lo, 78);                                                                                    \
                lo = _mm_xor_si128(lo, r);                                                                                         \
                r = _mm_clmulepi64_si128(lo, poly, 0x10);                                                                          \
                lo = _mm_shuffle_epi32(lo, 78);                                                                                    \
                lo = _mm_xor_si128(lo, r);                                                                                         \
                ghash = _mm_xor_si128(hi, lo);                                                                                     \
            });                                                                                                                    \
        return ghash;                                                                                                              \
    } while (0)

static inline __m128i ghash6(ptls_fusion_aesgcm_context_t *ctx, const __m128i *gdata, __m128i ghash)
{
#define FUNC(b1, b2, b3, b4, b5, b6, b7, b8, b9) {b1} {b2} {b3} {b4} {b5} {b6} {b7} {b8} {b9}
    GHASH6(FUNC);
#undef FUNC
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

static inline __m128i aesecb6ghash6(ptls_fusion_aesgcm_context_t *ctx, __m128i *data, const __m128i *gdata, __m128i ghash)
{
    GHASH6(AESECB6);
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

static inline void finish_gcm(ptls_fusion_aesgcm_context_t *ctx, __m128i *dst, const __m128i *dst_ghash, const __m128i *aad, size_t aadlen,
                       __m128i ghash, __m128i ac, __m128i ek0)
{
    const __m128i *enc = dst_ghash;
    size_t enclen = (const uint8_t *)dst - (const uint8_t *)enc;
    __m128i gdata[6];
    int gdata_index;

    while (1) {
        gdata_index = 0;
        if (aadlen != 0) {
            while (aadlen >= 16) {
                gdata[gdata_index++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
                if (gdata_index == 6)
                    goto GHASH6;
            }
            if (aadlen != 0) {
                gdata[gdata_index++] = loadn(aad, aadlen);
                aadlen = 0;
                if (gdata_index == 6)
                    goto GHASH6;
            }
        }
        if (enclen != 0) {
            while (enclen >= 16) {
                gdata[gdata_index++] = _mm_loadu_si128(enc++);
                enclen -= 16;
                if (gdata_index == 6)
                    goto GHASH6;
            }
            if (enclen != 0) {
                gdata[gdata_index++] = loadn(enc, enclen);
                enclen = 0;
                if (gdata_index == 6)
                    goto GHASH6;
            }
        }
        __m128i bswap64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
        gdata[gdata_index++] = _mm_shuffle_epi8(ac, bswap64);
        break;

    GHASH6:
        ghash = ghash6(ctx, gdata, ghash);
    }

    /* final */
#if 0
    for (int i = 0; i < gdata_index; ++i)
        ghash = gfmul(_mm_xor_si128(ghash, _mm_shuffle_epi8(gdata[i], bswap8)), ctx->ghash[0].H);
#else
    ghash = ghashn(ctx, gdata, gdata_index, ghash);
#endif
    __m128i tag = _mm_shuffle_epi8(ghash, bswap8);
    tag = _mm_xor_si128(tag, ek0);
    _mm_storeu_si128(dst, tag);
}

void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, const void *iv, const void *_aad, size_t aadlen, void *_dst,
                                const void *_src, size_t srclen)
{
    __m128i bswap64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7), one = _mm_set_epi32(0, 1, 0, 0);
    __m128i ctr, ek0, bits[6], gdatabuf[6], ghash = _mm_setzero_si128();
    int ek0_encrypted = 0;
    __m128i ac = _mm_set_epi32(0, (int)srclen * 8, 0, (int)aadlen * 8);

    // src and dst are updated after the chunk is processed
    const __m128i *src = _src;
    __m128i *dst = _dst;
    // aad and src_ghash are updated before the chunk is processed (i.e., when the pointers are fed indo the processor)
    const __m128i *aad = _aad, *dst_ghash = dst;

    /* build counter */
    ctr = loadn(iv, PTLS_AESGCM_IV_SIZE);
    ctr = _mm_shuffle_epi8(ctr, bswap8);
    ctr = _mm_add_epi64(ctr, one);
    ek0 = _mm_shuffle_epi8(ctr, bswap64);

/* setup the counters (we can always run in full), but use the last slot for calculating ek0, if possible */
#define SETUP_BITS()                                                                                                               \
    do {                                                                                                                           \
        for (int i = 0; i < 5; ++i) {                                                                                              \
            ctr = _mm_add_epi64(ctr, one);                                                                                         \
            bits[i] = _mm_shuffle_epi8(ctr, bswap64);                                                                              \
        }                                                                                                                          \
        if (PTLS_LIKELY(srclen > 16 * 5)) {                                                                                        \
            ctr = _mm_add_epi64(ctr, one);                                                                                         \
            bits[5] = _mm_shuffle_epi8(ctr, bswap64);                                                                              \
        } else {                                                                                                                   \
            assert(!ek0_encrypted);                                                                                                \
            bits[5] = ek0;                                                                                                         \
            ek0_encrypted = 1;                                                                                                     \
        }                                                                                                                          \
    } while (0)

    /* build the first AES bits */
    SETUP_BITS();
    aesecb6(ctx, bits);

    /* the main loop */
    while (PTLS_LIKELY(srclen >= 6 * 16)) {
        /* apply the bits */
        for (int i = 0; i < 6; ++i)
            _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src++), bits[i]));
        srclen -= 6 * 16;

        /* setup bits */
        SETUP_BITS();

        /* setup gdata */
        const __m128i *gdata;
        if (PTLS_UNLIKELY(aadlen != 0)) {
            for (int i = 0; i < 6; ++i) {
                if (aadlen < 16) {
                    if (aadlen != 0) {
                        gdatabuf[i++] = loadn(aad, aadlen);
                        aadlen = 0;
                    }
                    while (i < 6)
                        gdatabuf[i++] = _mm_loadu_si128(dst_ghash++);
                    break;
                }
                gdatabuf[i++] = _mm_loadu_si128(aad++);
                aadlen -= 16;
            }
            gdata = gdatabuf;
        } else {
            gdata = dst_ghash;
            dst_ghash += 6;
        }

        /* doit */
        ghash = aesecb6ghash6(ctx, bits, gdata, ghash);
    }

    /* apply the bit stream to the remainder */
    for (int i = 0; i < 6 && srclen != 0; ++i) {
        if (srclen < 16) {
            storen(dst, srclen, _mm_xor_si128(loadn(src, srclen), bits[i]));
            dst = (__m128i *)((uint8_t *)dst + srclen);
            srclen = 0;
            break;
        }
        _mm_storeu_si128(dst++, _mm_xor_si128(_mm_loadu_si128(src++), bits[i]));
        srclen -= 16;
    }

    if (ek0_encrypted) {
        ek0 = bits[5];
    } else {
        assert(!"FIXME calculate ek0");
    }

    finish_gcm(ctx, dst, dst_ghash, aad, aadlen, ghash, ac, ek0);
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
    for (int i = 1; i < 6; ++i)
        ctx->ghash[i].H = gfmul(ctx->ghash[i - 1].H, ctx->ghash[0].H);
    for (int i = 0; i < 6; ++i) {
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
