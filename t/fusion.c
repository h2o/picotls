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
    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(userkey, 16384);

    {
        static const uint8_t iv[12] = {};
        uint8_t encrypted[sizeof(plaintext) + 16];
        ptls_fusion_aesgcm_encrypt(ctx, iv, "hello", 5, encrypted, plaintext, sizeof(plaintext));
        dump(encrypted, sizeof(encrypted));
    }

    { /* benchmark */
        static const uint8_t iv[12] = {}, aad[13] = {}, text[16384] = {};
        uint8_t encrypted[sizeof(text) + 16];
        for (int i = 0; i < 1000000; ++i) {
            ptls_fusion_aesgcm_encrypt(ctx, iv, aad, sizeof(aad), encrypted, text, sizeof(text));
            if (i == 0)
                dump(encrypted, sizeof(encrypted));
        }
    }

    return 0;
}
