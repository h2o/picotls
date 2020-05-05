/*
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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../deps/picotest/picotest.h"
#include "../lib/fusion.c"

static void dump(const void *_p, size_t len)
{
    const uint8_t *p = _p;
    for (size_t i = 0; i != len; ++i)
        printf("%02x", p[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    static const uint8_t userkey[16] = {};
    static const uint8_t plaintext[16] = {};
    __m128i ONE = _mm_set_epi32(0, 0, 0, 1), BSWAP64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7);
    ptls_fusion_aesgcm_context_t ctx;

    ptls_fusion_aesgcm_init(&ctx, userkey);

    if (1) { /* test */
        __m128i ecb6[6], ctr = _mm_setzero_si128();
        for (int i = 0; i < 6; ++i) {
            ctr = _mm_add_epi64(ctr, ONE);
            ecb6[i] = _mm_shuffle_epi8(ctr, bswap8);
        }
        aesecb6(&ctx, ecb6);
        __m128i gdata[6];
        for (int i = 0; i < 5; ++i)
            gdata[i] = ecb6[i + 1];
        gdata[5] = _mm_shuffle_epi8(_mm_set_epi32(0, 8 * 16 * 5, 0, 0), BSWAP64);
        __m128i dummy[6] = {}, ghash = {};
        ghash = aesecb6ghash6(&ctx, dummy, gdata, ghash);
        ghash = _mm_shuffle_epi8(ghash, bswap8);
        __m128i tag = _mm_xor_si128(ghash, ecb6[0]);
        dump(ecb6 + 1, 16);
        dump(ecb6 + 1, 16 * 5);
        dump(&tag, 16);

        {
            __m128i gx = {};
            gx = ghash6(&ctx, gdata, gx);
            gx = _mm_shuffle_epi8(gx, bswap8);
            tag = _mm_xor_si128(gx, ecb6[0]);
            dump(&tag, 16);
        }
    }

    { /* benchmark */
        __m128i test[300] = {}, ghash = {};
        __m128i ctr = _mm_setzero_si128();
        for (int i = 0; i < 300; ++i)
            memcpy(test + i, plaintext, 16);
        for (int i = 0; i < 5000000; ++i) {
            for (int j = 0; j < 300;) {
                __m128i bits[6];
                ctr = _mm_add_epi64(ctr, ONE);
                bits[0] = _mm_shuffle_epi8(ctr, BSWAP64);
                ctr = _mm_add_epi64(ctr, ONE);
                bits[1] = _mm_shuffle_epi8(ctr, BSWAP64);
                ctr = _mm_add_epi64(ctr, ONE);
                bits[2] = _mm_shuffle_epi8(ctr, BSWAP64);
                ctr = _mm_add_epi64(ctr, ONE);
                bits[3] = _mm_shuffle_epi8(ctr, BSWAP64);
                ctr = _mm_add_epi64(ctr, ONE);
                bits[4] = _mm_shuffle_epi8(ctr, BSWAP64);
                ctr = _mm_add_epi64(ctr, ONE);
                bits[5] = _mm_shuffle_epi8(ctr, BSWAP64);
                ghash = aesecb6ghash6(&ctx, bits, j == 0 ? test + 294 : test + j - 6, ghash);
                // aesecb4(&ctx, bits);
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[0]));
                ++j;
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[1]));
                ++j;
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[2]));
                ++j;
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[3]));
                ++j;
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[3]));
                ++j;
                _mm_storeu_si128(test + j, _mm_xor_si128(_mm_loadu_si128(test + j), bits[3]));
                ++j;
            }
        }
        dump(&ghash, sizeof(ghash));
    }

    return 0;
}
