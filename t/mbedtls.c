/*
 * Copyright (c) 2023, Christian Huitema
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "picotls/mbedtls.h"
#include "picotls/minicrypto.h"
#include "../deps/picotest/picotest.h"
#include "test.h"

typedef struct st_ptls_mbedtls_signature_scheme_t {
    uint16_t scheme_id;
    psa_algorithm_t hash_algo;
} ptls_mbedtls_signature_scheme_t;

typedef struct st_ptls_mbedtls_sign_certificate_t {
    ptls_sign_certificate_t super;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes;
    const ptls_mbedtls_signature_scheme_t *schemes;
} ptls_mbedtls_sign_certificate_t;

int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async,
                                  uint16_t *selected_algorithm, ptls_buffer_t *outbuf, ptls_iovec_t input,
                                  const uint16_t *algorithms, size_t num_algorithms);

static int random_trial()
{
    /* The random test is just trying to check that we call the API properly.
     * This is done by getting a vector of 1021 bytes, computing the sum of
     * all values, and comparing to theoretical min and max,
     * computed as average +- 8*standard deviation for sum of 1021 terms.
     * 8 random deviations results in an extremely low probability of random
     * failure.
     * Note that this does not actually test the random generator.
     */

    uint8_t buf[1021];
    uint64_t sum = 0;
    const uint64_t max_sum_1021 = 149505;
    const uint64_t min_sum_1021 = 110849;
    int ret = 0;

    ptls_mbedtls_random_bytes(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i++) {
        sum += buf[i];
    }
    if (sum > max_sum_1021 || sum < min_sum_1021) {
        ret = -1;
    }

    return ret;
}

static void test_random(void)
{
    if (random_trial() != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_secp256r1(void)
{
    test_key_exchange(&ptls_mbedtls_secp256r1, &ptls_minicrypto_secp256r1);
    test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_mbedtls_secp256r1);
}

static void test_x25519(void)
{
    test_key_exchange(&ptls_mbedtls_x25519, &ptls_minicrypto_x25519);
    test_key_exchange(&ptls_minicrypto_x25519, &ptls_mbedtls_x25519);
}

static void test_key_exchanges(void)
{
    subtest("secp256r1", test_secp256r1);
    subtest("x25519", test_x25519);
}

/*
Sign certificate implements a callback:

if ((ret = tls->ctx->sign_certificate->cb(
tls->ctx->sign_certificate, tls, tls->is_server ? &tls->server.async_job : NULL, &algo, sendbuf,
ptls_iovec_init(data, datalen), signature_algorithms != NULL ? signature_algorithms->list : NULL,
signature_algorithms != NULL ? signature_algorithms->count : 0)) != 0) {

or:

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *outbuf, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)

The callback "super" type is ptls_sign_certificate_t, defined by the macro:
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms);

The notation is simple: input buffer and supported algorithms as input, selected algo and output buffer as output.
Output buffer is already partially filled.

*/

#define ASSET_RSA_KEY "t/assets/rsa/key.pem"
#define ASSET_RSA_PKCS8_KEY "t/assets/rsa-pkcs8/key.pem"
#define ASSET_SECP256R1_KEY "t/assets/secp256r1/key.pem"
#define ASSET_SECP384R1_KEY "t/assets/secp384r1/key.pem"
#define ASSET_SECP521R1_KEY "t/assets/secp521r1/key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "t/assets/secp256r1-pkcs8/key.pem"
#define ASSET_ED25519_KEY "t/assets/ed25519/key.pem"
#define ASSET_NO_SUCH_FILE "t/assets/no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "t/assets/not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "t/assets/rsa/cert.pem"
#define ASSET_RSA_PKCS8_CERT "t/assets/rsa-pkcs8/cert.pem"
#define ASSET_SECP256R1_CERT "t/assets/secp256r1/cert.pem"
#define ASSET_SECP384R1_CERT "t/assets/secp384r1/cert.pem"
#define ASSET_SECP521R1_CERT "t/assets/secp521r1/cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "t/assets/secp256r1-pkcs8/cert.pem"
#define ASSET_ED25519_CERT "t/assets/ed25519/cert.pem"
#define ASSET_TEST_CA "data/test-ca.crt"

int test_load_one_file(char const* path)
{
    size_t n;
    unsigned char *buf;
    int ret = ptls_mbedtls_load_file(path, &buf, &n);
    if (ret != 0) {
        printf("Cannot load file from: %s, ret = %d (0x%x, -0x%x)\n", path, ret, ret, (int16_t)-ret);
    }
    else if (n == 0) {
        printf("File %s is empty\n", path);
        ret = -1;
    }
    else if (buf[n] != 0) {
        printf("Buffer from %s is not null terminated\n", path);
        ret = -1;
    }
    if (buf != NULL) {
        free(buf);
    }
    return ret;
}

static void test_load_file_key()
{
    int ret = test_load_one_file(ASSET_RSA_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_file_cert()
{
    int ret = test_load_one_file(ASSET_SECP256R1_PKCS8_CERT);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

void test_load_file()
{
    subtest("load file key", test_load_file_key());
    subtest("load file cert", test_load_file_cert);
}

int test_load_one_der_key(char const *path)
{
    int ret = -1;
    unsigned char hash[32];
    const unsigned char h0[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                  17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    ptls_context_t ctx = {0};

    ret = ptls_mbedtls_load_private_key(&ctx, path);
    if (ret != 0) {
        printf("Cannot create sign_certificate from: %s\n", path);
        ret = -1;
    } else if (ctx.sign_certificate == NULL) {
        printf("Sign_certificate not set in ptls context for: %s\n", path);
        ret = -1;
    } else {
        /* Try to sign something */
        int ret;
        ptls_mbedtls_sign_certificate_t *signer =
            (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)ctx.sign_certificate) -
                                                offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        /* get the key algorithm */
        ptls_buffer_t outbuf;
        uint8_t outbuf_smallbuf[256];
        ptls_iovec_t input = {hash, sizeof(hash)};
        uint16_t selected_algorithm = 0;
        int num_algorithms = 0;
        uint16_t algorithms[16];
        memcpy(hash, h0, 32);
        while (signer->schemes[num_algorithms].scheme_id != UINT16_MAX && num_algorithms < 16) {
            algorithms[num_algorithms] = signer->schemes[num_algorithms].scheme_id;
            num_algorithms++;
        }

        ptls_buffer_init(&outbuf, outbuf_smallbuf, sizeof(outbuf_smallbuf));

        ret = ptls_mbedtls_sign_certificate(ctx.sign_certificate, NULL, NULL, &selected_algorithm, &outbuf, input, algorithms,
                                            num_algorithms);
        if (ret == 0) {
            printf("Signed a message, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        } else {
            printf("Sign failed, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        ptls_buffer_dispose(&outbuf);
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}

static void test_load_rsa_key()
{
    int ret = test_load_one_der_key(ASSET_RSA_KEY);

    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp256r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP256R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp384r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP384R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp521r1_key()
{
    int ret = test_load_one_der_key(ASSET_SECP521R1_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_secp256r1_pkcs8_key()
{
    int ret = test_load_one_der_key(ASSET_SECP256R1_PKCS8_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_rsa_pkcs8_key()
{
    int ret = test_load_one_der_key(ASSET_RSA_PKCS8_KEY);
    if (ret != 0) {
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

void test_load_keys(void)
{
    subtest("load rsa key", test_load_rsa_key);
    subtest("load secp256r1 key", test_load_secp256r1_key);
    subtest("load secp384r1 key", test_load_secp384r1_key);
    subtest("load secp521r1 key", test_load_secp521r1_key);
    subtest("load secp521r1-pkcs8 key", test_load_secp256r1_pkcs8_key);
    subtest("load rsa-pkcs8 key", test_load_rsa_pkcs8_key);

    /* we do not test EDDSA keys, because they are not yet supported */
}

static void test_load_key_no_such_file()
{
    int ret = test_load_one_der_key(ASSET_NO_SUCH_FILE);
    if (ret == 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_key_not_a_pem_file()
{
    int ret = test_load_one_der_key(ASSET_NOT_A_PEM_FILE);
    if (ret == 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_key_not_a_key_file()
{
    int ret = test_load_one_der_key(ASSET_RSA_CERT);
    if (ret == 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_load_key_not_supported()
{
    int ret = test_load_one_der_key(ASSET_ED25519_KEY);
    if (ret == 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

/*
* Testing of failure modes.
* 
* Testing the various reasons why loading of key should fail:
* - key file does not exist
* - key file is empty, no PEM keyword
* - key file does not contain a key (we use a cert file for that)
* - key file is for ED25559, which is not supported
*/

static void test_load_key_fail()
{
    subtest("load key no such file", test_load_key_no_such_file);
    subtest("load key not a PEM file", test_load_key_not_a_pem_file);
    subtest("load key not a key file", test_load_key_not_a_key_file);
    subtest("load key not supported", test_load_key_not_supported);
}

/*
* End to end testing of signature and verifiers:
* The general scenario is:
* - prepare a signature of a test string using a simulated
*   server programmed with a private key and a certificate
*   list.
* - verify the signature in a simulated client programmed
*   with a list of trusted certificates.
* 
* The test is configured with the file names for the key,
* certificate list, and trusted certificates. 
* 
* Ideally, we should be able to run the test by mixing and 
* matching mbedtls server or clients with other backends.
* However, using openssl will require some plumbing,
* which will be done when integrating this code in 
* picotls. For now, we will only do self tests, and test with
* minicrypto if the key is supported.
* 
* Consider breaking out parts of this test in separate subtests,
* e.g., load certificate chain, verify certificate chain,
* extract key from certificare chain, verify signature.
*/

static const unsigned char test_sign_verify_message[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9 , 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64
};
const size_t test_sign_verify_message_size = sizeof(test_sign_verify_message);

static uint16_t test_sign_signature_algorithms[] = {
    0x0401, 0x0403, 0x501, 0x0503, 0x0601, 0x0603,
    0x0804, 0x0805, 0x0806, 0x0807, 0x0808
};

static size_t num_test_sign_signature_algorithms = sizeof(test_sign_signature_algorithms) / sizeof(uint16_t);

char const* test_sign_server_name = "test.example.com";

static int test_sign_init_server_mbedtls(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_mbedtls_load_private_key(ctx, key_path);
    if (ret == 0) {
        ret = picoquic_mbedtls_get_certs_from_file(cert_path, &ctx->certificates.list, &ctx->certificates.count);
    }
    return ret;
}

static int test_sign_init_server_minicrypto(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_minicrypto_load_private_key(ctx, key_path);
    if (ret == 0) {
        ret = ptls_load_certificates(ctx, cert_path);
    }
    return ret;
}

static void test_sign_free_certificates(ptls_context_t* ctx)
{
    if (ctx->certificates.list != NULL) {
        for (int i = 0; i < ctx->certificates.count; i++) {
            free(ctx->certificates.list[i].base);
        }
        free(ctx->certificates.list);
    }
    ctx->certificates.list = NULL;
    ctx->certificates.count = 0;
}

static void test_sign_free_context(ptls_context_t* ctx, int config)
{
    /* Free the server context */
    if (ctx == NULL) {
        return;
    }
    test_sign_free_certificates(ctx);
    if (ctx->sign_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_sign_certificate(ctx->sign_certificate);
            break;
        case 1:
        default:
            free(ctx->sign_certificate);
            ctx->sign_certificate = NULL;
        }
    }

    if (ctx->verify_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_verify_certificate(ctx);
            break;
        default:
            break;
        }
    }

    free(ctx);
}

static ptls_context_t* test_sign_set_ptls_context(char const* key_path, char const* cert_path, char const* trusted_path, int is_server, int config)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)malloc(sizeof(ptls_context_t));
    if (ctx == NULL) {
        return NULL;
    }

    memset(ctx, 0, sizeof(ptls_context_t));
    ctx->get_time = &ptls_get_time;

    switch (config) {
    case 0:
        ctx->random_bytes = ptls_mbedtls_random_bytes;
    case 1:
    default:
        break;
    }

    if (is_server) {
        /* First, create the "signer" plug-in */
        switch (config) {
        case 0: /* MbedTLS */
            ret = test_sign_init_server_mbedtls(ctx, key_path, cert_path);
            break;
        case 1: /* Minicrypto */
            ret = test_sign_init_server_minicrypto(ctx, key_path, cert_path);
            break;
        default:
            ret = -1;
            break;
        }
    }
    else {
        /* Initialize the client verify context */
        switch (config) {
        case 0: /* MbedTLS */
            ret = ptls_mbedtls_init_verify_certificate(ctx, trusted_path);
            break;
        default:
            ret = -1;
            break;
        }
    }

    if (ret != 0) {
        /* Release and return NULL */
        test_sign_free_context(ctx, config);
        ctx = NULL;
    }
    return ctx;
}

static int test_sign_verify_one(char const* key_path, char const * cert_path, char const * trusted_path, int server_config, int client_config)
{
    int ret = 0;
    ptls_context_t* server_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 1, server_config); 
    ptls_context_t* client_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 0, client_config);
    ptls_t* client_tls = NULL;
    ptls_t* server_tls = NULL;
    uint16_t selected_algorithm = 0;
    uint8_t signature_smallbuf[256];
    ptls_buffer_t signature;
    struct {
        int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
        void *verify_ctx;
    } certificate_verify;
    ptls_iovec_t input;
    input.base = (uint8_t *)test_sign_verify_message;
    input.len = test_sign_verify_message_size;

    ptls_buffer_init(&signature, signature_smallbuf, sizeof(signature_smallbuf));

    if (server_ctx == NULL || client_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Then, create a tls context for the server. */
        server_tls = ptls_new(server_ctx, 1);
        if (server_tls == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Then, create the signature messages */
        ret = server_ctx->sign_certificate->cb(server_ctx->sign_certificate, server_tls, NULL,
            &selected_algorithm, &signature, input,
            test_sign_signature_algorithms, num_test_sign_signature_algorithms);
        if (ret != 0) {
            printf("sign_certificate (%s) returns 0x%x\n", key_path, ret);
        }
    }

    if (ret == 0) {
        /* Then, create a tls context for the client. */
        client_tls = ptls_new(client_ctx, 0);
        if (client_tls == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* verify the certificates */
        ret = client_ctx->verify_certificate->cb(client_ctx->verify_certificate, client_tls, test_sign_server_name,
            &certificate_verify.cb, &certificate_verify.verify_ctx,
            server_ctx->certificates.list, server_ctx->certificates.count);
        if (ret != 0) {
            printf("verify_certificate (%s) returns 0x%x\n", cert_path, ret);
        }
        /* verify the signature */
        if (ret == 0) {
            ptls_iovec_t sig;
            sig.base = signature.base;
            sig.len = signature.off;

            ret = certificate_verify.cb(certificate_verify.verify_ctx, selected_algorithm, input, sig);
            if (ret != 0) {
                printf("verify_signature (%s) returns 0x%x\n", key_path, ret);
            }
        }
        else if (certificate_verify.cb != NULL) {
            ptls_iovec_t empty;
            empty.base = NULL;
            empty.len = 0;
            (void)certificate_verify.cb(certificate_verify.verify_ctx, 0, empty, empty);
        }
    }
    if (ret == 0) {
        printf("verify_signature (%s) and cert (%s) succeeds\n", key_path, cert_path);
    }

    ptls_buffer_dispose(&signature);

    if (client_tls != NULL) {
        ptls_free(client_tls);
    }
    if (server_tls != NULL) {
        ptls_free(server_tls);
    }

    test_sign_free_context(server_ctx, server_config);
    test_sign_free_context(client_ctx, client_config);

    return ret;
}

static void test_sign_verify_rsa_mbedtls_mbedtls()
{
    int ret = test_sign_verify_one(ASSET_RSA_KEY, ASSET_RSA_CERT, ASSET_TEST_CA, 0, 0);
    if (ret != 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_sign_verify_secp256r1_mbedtls_mbedtls()
{
    ret = test_sign_verify_one(ASSET_SECP256R1_KEY, ASSET_SECP256R1_CERT, ASSET_SECP256R1_CERT, 0, 0);
    if (ret != 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_sign_verify_secp384r1_mbedtls_mbedtls()
{
    int ret = test_sign_verify_one(ASSET_SECP384R1_KEY, ASSET_SECP384R1_CERT, ASSET_SECP384R1_CERT, 0, 0);
    if (ret != 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_sign_verify_secp521r1_mbedtls_mbedtls()
{
    ret = test_sign_verify_one(ASSET_SECP521R1_KEY, ASSET_SECP521R1_CERT, ASSET_SECP521R1_CERT, 0, 0);
    if (ret != 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

static void test_sign_verify_secp256r1_pkcs8_mbedtls_mbedtls()
{
    ret = test_sign_verify_one(ASSET_SECP256R1_PKCS8_KEY, ASSET_SECP256R1_PKCS8_CERT, ASSET_SECP256R1_PKCS8_CERT, 0, 0);
    if (ret != 0){
        ok(!"fail");
        return;
    }
    ok(!!"success");
}

/* TODO: all these tests are failing, because we do not have the 
* proper combination of hostname and certificate. Fix that, then
* enable the test.
* 
* TODO: add tests of minicrypto server and mbedtls client.
* TODO: add tests of mbedtls versus openssl.
* TODO: add negative testing.
 */

static void test_sign_verify_end_to_end()
{
    subtest("sign verify rsa mbedtls mbedtls", test_sign_verify_rsa_mbedtls_mbedtls);
    subtest("sign verify secp256r1 mbedtls mbedtls", test_sign_verify_secp256r1_mbedtls_mbedtls);
    subtest("sign verify secp384r1 mbedtls mbedtls", test_sign_verify_secp384r1_mbedtls_mbedtls);
    subtest("sign verify secp521r1 mbedtls mbedtls", test_sign_verify_secp521r1_mbedtls_mbedtls);
    subtest("sign verify secp256r1 pkcs8 mbedtls mbedtls", test_sign_verify_secp256r1_pkcs8_mbedtls_mbedtls);

    return ret;
}


DEFINE_FFX_AES128_ALGORITHMS(mbedtls);
DEFINE_FFX_CHACHA20_ALGORITHMS(mbedtls);

int main(int argc, char **argv)
{
    /* Initialize the PSA crypto library. */
    if (psa_crypto_init() != PSA_SUCCESS) {
        note("psa_crypto_init fails.");
        return done_testing();
    }

    /* Test of the port of the mbedtls random generator */
    subtest("random", test_random);
    subtest("key_exchanges", test_key_exchanges);

    ADD_FFX_AES128_ALGORITHMS(mbedtls);
    ADD_FFX_CHACHA20_ALGORITHMS(mbedtls);

    /* minicrypto contexts used as peer for valiation */
    ptls_iovec_t secp256r1_certificate = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);
    ptls_minicrypto_secp256r1sha256_sign_certificate_t minicrypto_sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &minicrypto_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t minicrypto_ctx = {.random_bytes = ptls_minicrypto_random_bytes,
                                     .get_time = &ptls_get_time,
                                     .key_exchanges = ptls_minicrypto_key_exchanges,
                                     .cipher_suites = ptls_minicrypto_cipher_suites,
                                     .certificates = {&secp256r1_certificate, 1},
                                     .sign_certificate = &minicrypto_sign_certificate.super};

    /* context using mbedtls as backend; minicrypto is used for signing certificate as the mbedtls backend does not (yet) have the
     * capability */
    ptls_minicrypto_secp256r1sha256_sign_certificate_t mbedtls_sign_certificate;
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &mbedtls_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t mbedtls_ctx = {.random_bytes = ptls_mbedtls_random_bytes,
                                  .get_time = &ptls_get_time,
                                  .key_exchanges = ptls_mbedtls_key_exchanges,
                                  .cipher_suites = ptls_mbedtls_cipher_suites,
                                  .certificates = {&secp256r1_certificate, 1},
                                  .sign_certificate = &mbedtls_sign_certificate.super};

    ctx = &mbedtls_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("selt-test", test_picotls);

    ctx = &mbedtls_ctx;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls);

    ctx = &minicrypto_ctx;
    ctx_peer = &mbedtls_ctx;
    subtest("minicrypto vs.", test_picotls);

    /* Test loading file in memory */
    subtest("test load file", test_load_file);

    /* test loading of keys in memory and capability to sign  */
    subtest("test load keys", test_load_keys);

    /* Test that loading bad files or bad keys fails */
    subtest("test load key failures", test_load_key_fail);

    /* End to end test of signing and verifying certicates */
    subtest("test sign verify end to end", test_sign_verify_end_to_end);

    /* Deinitialize the PSA crypto library. */
    mbedtls_psa_crypto_free();

    return done_testing();
}
