/*
 * Copyright (c) 2022 Fastly, Kazuho Oku
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
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <assert.h>
#include <string.h>
#include "picotls.h"
#include "picotls/hpke.h"
#include "../deps/picotest/picotest.h"
#include "test.h"
#include "../lib/hpke.c"

/* RFC 9180 A.1.1 */
void test_hpke(ptls_hpke_kem_t *kem, ptls_aead_algorithm_t *aead)
{
    assert(kem->id == PTLS_HPKE_KEM_X25519_SHA256);
    assert(aead->hpke_id == PTLS_HPKE_AEAD_AES_128_GCM);

    static const uint8_t dh[] = {0xb3, 0xb5, 0xc1, 0x9e, 0xab, 0x3f, 0x08, 0x8a, 0xc1, 0x8f, 0x23, 0xf7, 0x74, 0xff, 0x64, 0x14,
                                 0xba, 0x4f, 0xde, 0x45, 0x40, 0x4d, 0x10, 0x08, 0x5e, 0xfc, 0x3e, 0x4d, 0xc9, 0xc7, 0x2e, 0x35},
                         expected_secret[] = {0xfe, 0x0e, 0x18, 0xc9, 0xf0, 0x24, 0xce, 0x43, 0x79, 0x9a, 0xe3,
                                              0x93, 0xc7, 0xe8, 0xfe, 0x8f, 0xce, 0x9d, 0x21, 0x88, 0x75, 0xe8,
                                              0x22, 0x7b, 0x01, 0x87, 0xc0, 0x4e, 0x7d, 0x2e, 0xa1, 0xfc},
                         expected_ciphertext[] = {0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2, 0x38, 0x10, 0xb4, 0xbe,
                                                  0x2a, 0xb4, 0xf8, 0x43, 0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5,
                                                  0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9, 0x6d, 0x87, 0x70, 0xac,
                                                  0x83, 0xd0, 0x7b, 0xea, 0x87, 0xe1, 0x3c, 0x51, 0x2a};
    static const char *info = "Ode on a Grecian Urn", *cleartext = "Beauty is truth, truth beauty", *aad = "Count-0";
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    int ret;

    assert(sizeof(expected_ciphertext) == strlen(cleartext) + aead->tag_size);

    /* derivation from DH shared secret */
    ret = dh_derive(kem, secret, ptls_iovec_init(X25519_CLIENT_PUBKEY, sizeof(X25519_CLIENT_PUBKEY) - 1),
                    ptls_iovec_init(X25519_SERVER_PUBKEY, sizeof(X25519_SERVER_PUBKEY) - 1), ptls_iovec_init(dh, sizeof(dh)));
    ok(ret == 0);
    assert(kem->hash->digest_size == sizeof(expected_secret));
    ok(memcmp(secret, expected_secret, sizeof(expected_secret)) == 0);

    { /* encryption */
        ptls_aead_context_t *enc;
        uint8_t ciphertext[sizeof(expected_ciphertext)];
        ret = key_schedule(kem, aead, &enc, 1, secret, ptls_iovec_init(info, strlen(info)));
        ok(ret == 0);
        ptls_aead_encrypt(enc, ciphertext, cleartext, strlen(cleartext), 0, aad, strlen(aad));
        ptls_aead_free(enc);
        ok(memcmp(ciphertext, expected_ciphertext, sizeof(ciphertext)) == 0);
    }

    { /* decryption */
        ptls_aead_context_t *dec;
        uint8_t text_recovered[strlen(cleartext)];
        ret = key_schedule(kem, aead, &dec, 0, secret, ptls_iovec_init(info, strlen(info)));
        ok(ret == 0);
        ok(ptls_aead_decrypt(dec, text_recovered, expected_ciphertext, sizeof(expected_ciphertext), 0, aad, strlen(aad)) ==
           strlen(cleartext));
        ptls_aead_free(dec);
    }
}
