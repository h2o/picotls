/*
 * Copyright (c) 2017 Fastly, Kazuho Oku
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
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include "picotls.h"
#include "picotls/openssl.h"

int main(int argc, char **argv)
{
    int ch;
    ptls_delegated_credential_t cred = {
        0x7f12, /* tied to draft-18 for  now */
        UINT32_MAX, /* valid_time */
        {NULL}, /* public_key */
        PTLS_SIGNATURE_RSA_PSS_SHA256 /* signature_schemes */
    };
    ptls_iovec_t signer_cert = {NULL};
    ptls_openssl_sign_certificate_t *signer = NULL;
    ptls_buffer_t output;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    while ((ch = getopt(argc, argv, "p:V:k:c:s:v:h")) != -1) {
        switch (ch) {
        case 'p': { /* public key */
            FILE *fp;
            if ((fp = fopen(optarg, "rb")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            EVP_PKEY *pkey;
            if ((pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "failed to load public key from file:%s\n", optarg);
                return 1;
            }
            cred.public_key.len = (size_t)i2d_PUBKEY(pkey, NULL);
            if ((cred.public_key.base = malloc(cred.public_key.len)) == NULL) {
                perror("no memory");
                return 1;
            }
            uint8_t *p = cred.public_key.base;
            i2d_PUBKEY(pkey, &p);
            EVP_PKEY_free(pkey);
            fclose(fp);
        } break;
        case 'V':
            if (sscanf(optarg, "%" PRIu32, &cred.valid_time) != 1) {
                fprintf(stderr, "failed to parse validtime\n");
                return 1;
            }
            break;
        case 'c': {
            FILE *fp; X509 *cert;
            if ((fp = fopen(optarg, "rb")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            if ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "failed to load certifiate from file:%s\n", optarg);
                return 1;
            }
            signer_cert.len = i2d_X509(cert, NULL);
            if ((signer_cert.base = malloc(signer_cert.len)) == NULL) {
                perror("no memory");
                return 1;
            }
            uint8_t *p = signer_cert.base;
            i2d_X509(cert, &p);
            X509_free(cert);
            fclose(fp);
        } break;
        case 'k': {
            FILE *fp; EVP_PKEY *pkey;
            if ((fp = fopen(optarg, "rb")) == NULL) {
                fprintf(stderr, "failed to open file:%s:%s\n", optarg, strerror(errno));
                return 1;
            }
            if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
                fprintf(stderr, "failed to load private key from file:%s\n", optarg);
                return 1;
            }
            if ((signer = malloc(sizeof(*signer))) == NULL) {
                perror("no memory");
                return 1;
            }
            if (ptls_openssl_init_sign_certificate(signer, pkey) != 0) {
                fprintf(stderr, "failed to setup the private key\n");
                return 1;
            }
            EVP_PKEY_free(pkey);
            fclose(fp);
        } break;
        case 's':
            if (sscanf(optarg, "%" PRIx16, &cred.signature_scheme) != 1) {
                fprintf(stderr, "failed to parse signature scheme as a hexadecimal number: %s\n", optarg);
                return 1;
            }
            break;
        case 'v':
            printf("oaenutsaou\n");
            return 0;
        case 'h':
            printf("%s -p <pubkeyfile.bin> -V <validTime> -c <certificate.pem> -k <certkey.pem> -s <sigscheme-hex>\n", argv[0]);
            return 0;
        default:
            assert("fixme");
            break;
        }
    }
    if (cred.public_key.base == NULL) {
        fprintf(stderr, "mandatory option -p is missing\n");
        return 1;
    }
    if (cred.valid_time == UINT32_MAX) {
        fprintf(stderr, "mandatory option -V is missing\n");
        return 1;
    }
    if (signer == NULL) {
        fprintf(stderr, "mandatory option -k is missing\n");
        return 1;
    }
    if (signer_cert.base == NULL) {
        fprintf(stderr, "mandatory option -c is missing\n");
        return 1;
    }
    argc -= optind;
    argv += optind;

    ptls_buffer_init(&output, "", 0);
    if (ptls_sign_delegated_credential(&signer->super, &output, &cred, signer_cert) != 0) {
        fprintf(stderr, "failed to create a delegated credential\n");
        return 1;
    }

    fwrite(output.base, 1, output.off, stdout);

    return 0;
}
