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
#include <openssl/bio.h>
#include <openssl/pem.h>
#include "../deps/picotest/picotest.h"
#include "../lib/openssl.c"
#include "test.h"

#define RSA_PRIVATE_KEY                                                                                                            \
    "-----BEGIN RSA PRIVATE KEY-----\n"                                                                                            \
    "MIIEowIBAAKCAQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6\n"                                                           \
    "A/Z+bViFlfEgL37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9\n"                                                           \
    "C7WcNcshpSdm2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7\n"                                                           \
    "ntPW/XCchVf+ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDy\n"                                                           \
    "OxiNkLFLvUdT4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MI\n"                                                           \
    "uDo7Vhkq5+TCqXsIFNbjy0taOoPRvUbPsbqFlQIDAQABAoIBAQCWcUv1wjR/2+Nw\n"                                                           \
    "B+Swp267R9bt8pdxyK6f5yKrskGErremiFygMrFtVBQYjws9CsRjISehSkN4GqjE\n"                                                           \
    "CweygJZVJeL++YvUmQnvFJSzgCjXU6GEStbOKD/A7T5sa0fmzMhOE907V+kpAT3x\n"                                                           \
    "E1rNRaP/ImJ1X1GjuefVb0rOPiK/dehFQWfsUkOvh+J3PU76wcnexxzJgxhVxdfX\n"                                                           \
    "qNa7UDsWzTImUjcHIfnhXc1K/oSKk6HjImQi/oE4lgoJUCEDaUbq0nXNrM0EmTTv\n"                                                           \
    "OQ5TVP5Lds9p8UDEa55eZllGXam0zKjhDKtkQ/5UfnxsAv2adY5cuH+XN0ExfKD8\n"                                                           \
    "wIZ5qINtAoGBAPRbQGZZkP/HOYA4YZ9HYAUQwFS9IZrQ8Y7C/UbL01Xli13nKalH\n"                                                           \
    "xXdG6Zv6Yv0FCJKA3N945lEof9rwriwhuZbyrA1TcKok/s7HR8Bhcsm2DzRD5OiC\n"                                                           \
    "3HK+Xy+6fBaMebffqBPp3Lfj/lSPNt0w/8DdrKBTw/cAy40g0n1zEu07AoGBAPHJ\n"                                                           \
    "V4IfQBiblCqDh77FfQRUNR4hVbbl00Gviigiw563nk7sxdrOJ1edTyTOUBHtM3zg\n"                                                           \
    "AT9sYz2CUXvsyEPqzMDANWMb9e2R//NcP6aM4k7WQRnwkZkp0WOIH95U2o1MHCYc\n"                                                           \
    "5meAHVf2UMl+64xU2ZfY3rjMmPLjWMt0hKYsOmtvAoGAClIQVkJSLXtsok2/Ucrh\n"                                                           \
    "81TRysJyOOe6TB1QNT1Gn8oiKMUqrUuqu27zTvM0WxtrUUTAD3A7yhG71LN1p8eE\n"                                                           \
    "3ytAuQ9dItKNMI6aKTX0czCNU9fKQ0fDp9UCkDGALDOisHFx1+V4vQuUIl4qIw1+\n"                                                           \
    "v9adA+iFzljqP/uy6DmEAyECgYAyWCgecf9YoFxzlbuYH2rukdIVmf9M/AHG9ZQg\n"                                                           \
    "00xEKhuOd4KjErXiamDmWwcVFHzaDZJ08E6hqhbpZN42Nhe4Ms1q+5FzjCjtNVIT\n"                                                           \
    "jdY5cCdSDWNjru9oeBmao7R2I1jhHrdi6awyeplLu1+0cp50HbYSaJeYS3pbssFE\n"                                                           \
    "EIWBhQKBgG3xleD4Sg9rG2OWQz5IrvLFg/Hy7YWyushVez61kZeLDnt9iM2um76k\n"                                                           \
    "/xFNIW0a+eL2VxRTCbXr9z86hjc/6CeSJHKYFQl4zsSAZkaIJ0+HbrhDNBAYh9b2\n"                                                           \
    "mRdX+OMdZ7Z5J3Glt8ENFRqe8RlESMpAKxjR+dID0bjwAjVr2KCh\n"                                                                       \
    "-----END RSA PRIVATE KEY-----\n"

#define RSA_CERTIFICATE                                                                                                            \
    "-----BEGIN CERTIFICATE-----\n"                                                                                                \
    "MIICqDCCAZACCQDI5jeEvExN+TANBgkqhkiG9w0BAQUFADAWMRQwEgYDVQQDEwtl\n"                                                           \
    "eGFtcGxlLmNvbTAeFw0xNjA5MzAwMzQ0NTFaFw0yNjA5MjgwMzQ0NTFaMBYxFDAS\n"                                                           \
    "BgNVBAMTC2V4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n"                                                           \
    "AQEA5soWzSG7iyawQlHM1yaX2dUAATUkhpbg2WPFOEem7E3zYzc6A/Z+bViFlfEg\n"                                                           \
    "L37cbDUb4pnOAHrrsjGgkyBYh5i9iCTVfCk+H6SOHZJORO1Tq8X9C7WcNcshpSdm\n"                                                           \
    "2Pa8hmv9hsHbLSeoPNeg8NkTPwMVaMZ2GpdmiyAmhzSZ2H9mzNI7ntPW/XCchVf+\n"                                                           \
    "ax2yt9haZ+mQE2NPYwHDjqCtdGkP5ZXXnYhJSBzSEhxfGckIiKDyOxiNkLFLvUdT\n"                                                           \
    "4ERSFBjauP2cSI0XoOUsiBxJNwHH310AU8jZbveSTcXGYgEuu2MIuDo7Vhkq5+TC\n"                                                           \
    "qXsIFNbjy0taOoPRvUbPsbqFlQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAwZQsG\n"                                                           \
    "E/3DQFBOnmBITFsaIVJVXU0fbfIjy3p1r6O9z2zvrfB1i8AMxOORAVjE5wHstGnK\n"                                                           \
    "3sLMjkMYXqu1XEfQbStQN+Bsi8m+nE/x9MmuLthpzJHXUmPYZ4TKs0KJmFPLTXYi\n"                                                           \
    "j0OrP0a5BNcyGj/B4Z33aaU9N3z0TWBwx4OPjJoK3iInBx80sC1Ig2PE6mDBxLOg\n"                                                           \
    "5Ohm/XU/43MrtH8SgYkxr3OyzXTm8J0RFMWhYlo1uqR+pWV3TgacixNnUq5w5h4m\n"                                                           \
    "sqXcikh+j8ReNXsKnMOAfFo+HbRqyKWNE3DekCIiiQ5ds4A4SfT7pYyGAmBkAxht\n"                                                           \
    "sS919x2o8l97kaYf\n"                                                                                                           \
    "-----END CERTIFICATE-----\n"

static void test_ecdh_key_exchange(void)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_pubkey, client_secret, server_pubkey, server_secret;
    int ret;

    /* fail */
    ret = secp256r1_key_exchange(&server_pubkey, &server_secret, (ptls_iovec_t){NULL});
    ok(ret != 0);

    /* perform ecdh */
    ret = secp256r1_create_key_exchange(&ctx, &client_pubkey);
    ok(ret == 0);
    ret = secp256r1_key_exchange(&server_pubkey, &server_secret, client_pubkey);
    ok(ret == 0);
    ret = ctx->on_exchange(ctx, &client_secret, server_pubkey);
    ok(ret == 0);
    ok(client_secret.len == server_secret.len);
    ok(memcmp(client_secret.base, server_secret.base, client_secret.len) == 0);

    free(client_pubkey.base);
    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);
}

static void test_rsa_sign(void)
{
    ptls_openssl_context_t *ctx = ptls_openssl_context_new();
    setup_server_context(ctx);

    ok(select_compatible_signature_algorithm(ctx->servers.entries[0]->sign_ctx, (uint16_t[]){PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256},
                                             1) == UINT16_MAX);
    ok(select_compatible_signature_algorithm(ctx->servers.entries[0]->sign_ctx,
                                             (uint16_t[]){PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_SHA256},
                                             2) == PTLS_SIGNATURE_RSA_PSS_SHA256);

    const void *message = "hello world";
    ptls_iovec_t signature;
    ok(rsapss_sign(ctx->servers.entries[0]->sign_ctx, &signature, ptls_iovec_init(message, strlen(message))) == 0);

    /* TODO verify */

    ptls_openssl_context_free(ctx);
}

void test_openssl(void)
{
    subtest("ecdh-key-exchange", test_ecdh_key_exchange);
    subtest("rsa-sign", test_rsa_sign);
}

void setup_server_context(ptls_openssl_context_t *ctx)
{
    BIO *bio = BIO_new_mem_buf(RSA_PRIVATE_KEY, strlen(RSA_PRIVATE_KEY));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL || !"failed to load private key");
    BIO_free(bio);

    bio = BIO_new_mem_buf(RSA_CERTIFICATE, strlen(RSA_CERTIFICATE));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL || !!"failed to load certificate");
    BIO_free(bio);

    STACK_OF(X509) *certs = sk_X509_new(NULL);
    sk_X509_push(certs, cert);
    ptls_openssl_context_register_server(ctx, "example.com", pkey, certs);
    sk_X509_free(certs);

    X509_free(cert);
    EVP_PKEY_free(pkey);
}
