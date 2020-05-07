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
    for (size_t i = 0; i != len; ++i) {
        if (i % 16 == 0 && i != 0)
            printf("-");
        printf("%02x", p[i]);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    static const uint8_t userkey[16] = {};
    static const uint8_t plaintext[16] = {};
    ptls_fusion_aesgcm_context_t ctx;

    ptls_fusion_aesgcm_init(&ctx, userkey);

    {
        static const uint8_t iv[12] = {};
        uint8_t encrypted[sizeof(plaintext) + 16];
        ptls_fusion_aesgcm_encrypt(&ctx, iv, "hello", 5, encrypted, plaintext, sizeof(plaintext));
        dump(encrypted, sizeof(encrypted));
    }

#if 1
    { /* benchmark */
        static const uint8_t iv[12] = {}, aad[13] = {}, text[16384] = {};
        uint8_t encrypted[sizeof(text) + 16];
        for (int i = 0; i < 1000000; ++i) {
            ptls_fusion_aesgcm_encrypt(&ctx, iv, aad, sizeof(aad), encrypted, text, sizeof(text));
            if (i == 0)
                dump(encrypted, sizeof(encrypted));
        }
    }
#else
    { /* benchmark (using ~16384 bytes block) */
        __m128i test[171 * 6] = {}, ghash = {};
        __m128i ctr = _mm_setzero_si128();
        for (int i = 0; i < 171 * 6; ++i)
            memcpy(test + i, plaintext, 16);
        for (int i = 0; i < 1000000; ++i) {
            for (int j = 0; j < 171;) {
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
                ghash = aesecb6ghash6(&ctx, bits, j == 0 ? test + 171 * 6 - 6 : test + j - 6, ghash);
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
#endif

    return 0;
}
