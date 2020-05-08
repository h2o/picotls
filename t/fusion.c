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
#include "picotls/fusion.h"
#include "../deps/picotest/picotest.h"

static const char *tostr(const void *_p, size_t len)
{
    static char *buf;

    if (buf != NULL)
        free(buf);
    buf = malloc(len * 2 + 1);

    const uint8_t *s = _p;
    char *d = buf;

    for (; len != 0; --len) {
        *d++ = "0123456789abcdef"[*s >> 4];
        *d++ = "0123456789abcdef"[*s & 0xf];
        ++s;
    }
    *d = '\0';

    return buf;
}

int main(int argc, char **argv)
{
    static const uint8_t zero[16384] = {}, one[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

    {
        ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(zero, 5 + 16);
        uint8_t encrypted[32];
        ptls_fusion_aesgcm_encrypt(ctx, zero, "hello", 5, encrypted, zero, 16, NULL, NULL);
        ok(strcmp(tostr(encrypted, sizeof(encrypted)), "0388dace60b6a392f328c2b971b2fe78973fbca65477bf4785b0d561f7e3fd6c") == 0);
        ptls_fusion_aesgcm_destroy(ctx);
    }

    { /* test capacity */
        ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(zero, 2);
        uint8_t encrypted[17];
        ptls_fusion_aesgcm_encrypt(ctx, zero, "a", 1, encrypted, "X", 1, NULL, NULL);
        ok(strcmp(tostr(encrypted + 1, 16), "27215ed81a702e3941c80577d52fcb57") == 0);
        ptls_fusion_aesgcm_destroy(ctx);
    }


    {
        ptls_fusion_aesgcm_context_t *aead = ptls_fusion_aesgcm_create(zero, sizeof(zero));
        ptls_fusion_aesecb_context_t *ecb = NULL;

        for (int i = 0; i < 2; ++i) {
            uint8_t encrypted[sizeof(zero) + 16], ecbvec[16];
#define DOIT(iv, aad, aadlen, ptlen, expected_tag)                                                                                 \
    do {                                                                                                                           \
        memset(ecbvec, 0, sizeof(ecbvec));                                                                                         \
        ptls_fusion_aesgcm_encrypt(aead, iv, aad, aadlen, encrypted, zero, ptlen, ecb, &ecbvec);                                   \
        ok(strcmp(tostr(encrypted + ptlen, 16), expected_tag) == 0);                                                               \
        if (i == 0) {                                                                                                              \
            ok(memcmp(ecbvec, zero, sizeof(ecbvec)) == 0);                                                                         \
        } else {                                                                                                                   \
            ok(strcmp(tostr(ecbvec, sizeof(ecbvec)), "b6aeaffa752dc08b51639731761aed00") == 0);                                    \
        }                                                                                                                          \
    } while (0)

            DOIT(zero, zero, 13, 17, "1b4e515384e8aa5bb781ee12549a2ccf");
            DOIT(zero, zero, 13, 32, "84030586f55adf8ac3c145913c6fd0f8");
            DOIT(zero, zero, 13, 64, "66165d39739c50c90727e7d49127146b");
            DOIT(zero, zero, 13, 65, "eb3b75e1d4431e1bb67da46f6a1a0edd");
            DOIT(zero, zero, 13, 79, "8f4a96c7390c26bb15b68865e6a861b9");
            DOIT(zero, zero, 13, 80, "5cc2554857b19e7a9e18d015feac61fd");
            DOIT(zero, zero, 13, 81, "5a65f0d4db36c981bf7babd11691fe78");
            DOIT(zero, zero, 13, 95, "6a8a51152efe928999a610d8a7b1df9d");
            DOIT(zero, zero, 13, 96, "6b9c468e24ed96010687f3880a044d42");
            DOIT(zero, zero, 13, 97, "1b4eb785b884a7d4fdebaff81c1c12e8");

            DOIT(zero, zero, 22, 1328, "0507baaece8d573774c94e8103821316");
            DOIT(zero, zero, 21, 1329, "dd70d59030eadb6313e778046540a253");
            DOIT(zero, zero, 20, 1330, "f1b456b955afde7603188af0124a32ef");

            DOIT(zero, zero, 13, 1337, "a22deec51250a7eb1f4384dea5f2e890");
            DOIT(zero, zero, 12, 1338, "42102b0a499b2efa89702ece4b0c5789");
            DOIT(zero, zero, 11, 1339, "9827f0b34252160d0365ffaa9364bedc");

            DOIT(zero, zero, 0, 80, "98885a3a22bd4742fe7b72172193b163");
            DOIT(zero, zero, 0, 96, "afd649fc51e14f3966e4518ad53b9ddc");

#undef DOIT

            ecb = malloc(sizeof(*ecb));
            ptls_fusion_aesecb_init(ecb, one);
        }

        ptls_fusion_aesecb_dispose(ecb);
        free(ecb);
        ptls_fusion_aesgcm_destroy(aead);
    }

    return done_testing();
}
