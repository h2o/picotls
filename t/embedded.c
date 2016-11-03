/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#include "../lib/cifra.c"
#include "../lib/uecc.c"
#include "test.h"

/* raw private key and certificate using secp256v1 */
#define PRIVATE_KEY                                                                                                                \
    "\x92\xbe\xc7\x34\x58\xc8\xa7\x1a\x25\x22\xf0\x29\x81\xc8\xca\x33\x84\xa5\xca\x0b\x8f\x0f\x19\x94\x83\xcb\xaf\x3f\x3d\x9f\x19" \
    "\xa1"
#define CERTIFICATE                                                                                                                \
    "\x30\x82\x01\x97\x30\x82\x01\x3f\xa0\x03\x02\x01\x02\x02\x09\x00\xa5\x28\xf1\x53\xe1\x92\xb8\x1c\x30\x09\x06\x07\x2a\x86\x48" \
    "\xce\x3d\x04\x01\x30\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x13\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x1e\x17" \
    "\x0d\x31\x36\x31\x31\x30\x33\x30\x37\x31\x33\x32\x39\x5a\x17\x0d\x32\x36\x31\x31\x30\x31\x30\x37\x31\x33\x32\x39\x5a\x30\x16" \
    "\x31\x14\x30\x12\x06\x03\x55\x04\x03\x13\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x30\x59\x30\x13\x06\x07\x2a\x86\x48" \
    "\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00\x04\x73\x47\xc4\x07\x56\x9a\x5a\x83\xa2\x49\xba\x34\x73" \
    "\x66\xd8\xb5\x95\x1e\xd6\xe9\x4e\xaf\x76\x09\x9f\x96\xb6\xb6\xab\xd3\xb9\xf0\x3e\x96\x10\x6f\xb2\xb4\x42\x93\x95\xfc\x30\x61" \
    "\x3b\xb4\x4b\xa1\x46\x92\xec\xf9\xf1\x0f\x7a\x25\x5c\x87\x29\x3e\x23\x56\x77\x91\xa3\x77\x30\x75\x30\x1d\x06\x03\x55\x1d\x0e" \
    "\x04\x16\x04\x14\x24\x7a\x07\x7b\x93\xd2\x3a\x60\x5e\xea\xb3\xdf\x21\xdf\x02\x63\x7d\x89\x40\xdd\x30\x46\x06\x03\x55\x1d\x23" \
    "\x04\x3f\x30\x3d\x80\x14\x24\x7a\x07\x7b\x93\xd2\x3a\x60\x5e\xea\xb3\xdf\x21\xdf\x02\x63\x7d\x89\x40\xdd\xa1\x1a\xa4\x18\x30" \
    "\x16\x31\x14\x30\x12\x06\x03\x55\x04\x03\x13\x0b\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d\x82\x09\x00\xa5\x28\xf1\x53\xe1" \
    "\x92\xb8\x1c\x30\x0c\x06\x03\x55\x1d\x13\x04\x05\x30\x03\x01\x01\xff\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x04\x01\x03\x47\x00" \
    "\x30\x44\x02\x20\x3f\xfc\x14\x45\xa4\xc6\x21\x37\xa9\x4a\x6b\x79\x4d\x86\xea\x48\x2c\xa8\xea\xb8\x18\xd9\xc9\x94\xd0\x15\x38" \
    "\xa5\xfd\x23\xf1\xb0\x02\x20\x2e\xd4\x93\xfe\x19\xfa\x31\x82\xa0\xfe\xa2\x04\xbd\xf4\x8b\x68\xdb\xee\x7a\xe8\x33\x2c\xe1\x35" \
    "\x6d\xdc\x08\x37\xfd\x49\x35\x90"

static void test_secp256r1_key_exchange(void)
{
    test_key_exchange(&ptls_embedded_secp256r1);
}

static void test_x25519_key_exchange(void)
{
    test_key_exchange(&ptls_embedded_x25519);
}

static void test_secp256r1_sign(void)
{
    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE], priv[SECP256R1_PRIVATE_KEY_SIZE];
    ptls_iovec_t sig;

    uECC_make_key(pub, priv, uECC_secp256r1());
    ok(secp256r1sha256_sign(priv, &sig, ptls_iovec_init(msg, 32)) == 0);
    ok(sig.len == SECP256R1_SIGNATURE_SIZE);
    ok(uECC_verify(pub, (void *)msg, 32, sig.base, uECC_secp256r1()));

    free(sig.base);
}

int main(int argc, char **argv)
{
    subtest("secp256r1", test_secp256r1_key_exchange);
    subtest("x25519", test_x25519_key_exchange);
    subtest("secp256r1-sign", test_secp256r1_sign);

    ptls_embedded_lookup_certificate_t lookup_certificate;
    ptls_iovec_t key = ptls_iovec_init(PRIVATE_KEY, sizeof(PRIVATE_KEY) - 1),
                 cert = ptls_iovec_init(CERTIFICATE, sizeof(CERTIFICATE) - 1);
    ptls_embedded_init_lookup_certificate(&lookup_certificate);
    ptls_embedded_lookup_certificate_add_identity(&lookup_certificate, "example.com", PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, key,
                                                  &cert, 1);

    ptls_context_t ctxbuf = {ptls_embedded_random_bytes, ptls_embedded_key_exchanges, ptls_embedded_cipher_suites,
                             &lookup_certificate.super};
    ctx = ctx_peer = &ctxbuf;

    subtest("picotls", test_picotls);

    return done_testing();
    return done_testing();
}
