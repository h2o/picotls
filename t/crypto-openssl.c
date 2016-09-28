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
#include <string.h>
#include "../deps/picotest/picotest.h"
#include "../lib/crypto-openssl.c"

static void test_ecdh_key_exchange(void)
{
    ptls_iovec_t pubkey, secret;
    int ret;

    /* fail */
    ret = secp256r1_key_exchange(&pubkey, &secret, (ptls_iovec_t){NULL});
    ok(ret != 0);

    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *bn_ctx = BN_CTX_new();

    EC_KEY *testkey = ecdh_gerenate_key(group);
    ptls_iovec_t testpub = x9_62_encode_point(group, EC_KEY_get0_public_key(testkey), bn_ctx);
    assert(testpub.base != NULL);

    ret = x9_62_key_exchange(group, &pubkey, &secret, testpub, bn_ctx);
    ok(ret == 0);

    EC_POINT *libpub = x9_62_decode_point(group, pubkey, bn_ctx);
    ok(libpub != NULL);

    ptls_iovec_t testsecret = {malloc(secret.len), secret.len};
    ret = ECDH_compute_key(testsecret.base, testsecret.len, libpub, testkey, NULL);
    ok(ret > 0);

    ok(memcmp(secret.base, testsecret.base, secret.len) == 0);

    free(pubkey.base);
    free(secret.base);
    free(testsecret.base);
    EC_POINT_free(libpub);
    EC_KEY_free(testkey);
    BN_CTX_free(bn_ctx);
    EC_GROUP_free(group);
}

void test_crypto_openssl(void)
{
    subtest("ecdh-key-exchange", test_ecdh_key_exchange);
}
