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

    ctx.random_bytes = ptls_embedded_random_bytes;
    ctx.key_exchanges = ptls_embedded_key_exchanges;
    ctx.cipher_suites = ptls_embedded_cipher_suites;
    ptls_embedded_init_lookup_certificate(&lookup_certificate);
    ctx.lookup_certificate = &lookup_certificate.super;

    subtest("picotls", test_picotls);

    return done_testing();
    return done_testing();
}
