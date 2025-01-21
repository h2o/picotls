/*
 * Copyright (c) 2025 DeNA Co., Ltd., Kazuho Oku et al.
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
#include "minicrypto.h"
#include <stdlib.h>

#ifndef PTLS_HAVE_FUSION
#if defined(__AES__) && defined(__VAES__) && defined(__VPCLMULQDQ__) && defined(__PCLMUL__) && defined(__AVX2__)
#define PTLS_HAVE_FUSION                    1
#else
#define PTLS_HAVE_FUSION                    0
#endif
#endif
#if PTLS_HAVE_FUSION
#include "fusion.h"
#endif

#if PTLS_USE_OPENSSL

#include <stdio.h>
#include "openssl.h"
#include <openssl/bio.h>
#include <openssl/pem.h>

#if PTLS_HAVE_AEGIS
#include "libaegis.h"
#endif

void ptls_openssl_init_cipher_suites(ptls_context_t *ptls_ctx)
{
    static const ptls_cipher_suite_t *cipher_suites[] = {
        /* ciphers used with sha512 and sha384 */
#if PTLS_HAVE_AEGIS
        &ptls_openssl_aegis256sha512,
#endif
        &ptls_openssl_aes256gcmsha384,
        /* ciphers used with sha256 */
#if PTLS_HAVE_AEGIS
        &ptls_openssl_aegis128lsha256,
#endif
        &ptls_openssl_aes128gcmsha256,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        &ptls_openssl_chacha20poly1305sha256,
#endif
        NULL,
    };
#if PTLS_HAVE_FUSION
    static const ptls_cipher_suite_t ptls_fusion_aes128gcmsha256 = {
        .id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
        .aead = &ptls_fusion_aes128gcm,
        .hash = &ptls_openssl_sha256,
    };
    static const ptls_cipher_suite_t ptls_fusion_aes256gcmsha384 = {
        .id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
        .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384,
        .aead = &ptls_fusion_aes256gcm,
        .hash = &ptls_openssl_sha384,
    };
    static const ptls_cipher_suite_t *cipher_suites_fusion[] = {
#if PTLS_HAVE_AEGIS
        &ptls_openssl_aegis256sha512,
#endif
        &ptls_fusion_aes256gcmsha384,
#if PTLS_HAVE_AEGIS
        &ptls_openssl_aegis128lsha256,
#endif
        &ptls_fusion_aes128gcmsha256,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        &ptls_openssl_chacha20poly1305sha256,
#endif
        NULL,
    };
    if (ptls_fusion_is_supported_by_cpu()) {
        ptls_ctx->cipher_suites = cipher_suites_fusion;
        return;
    }
#endif
    ptls_ctx->cipher_suites = cipher_suites;
}

void ptls_openssl_init_key_exchanges(ptls_context_t *ptls_ctx)
{
    static const ptls_key_exchange_algorithm_t *key_exchanges[] = {
#if PTLS_OPENSSL_HAVE_X25519
        &ptls_openssl_x25519,
#endif
        &ptls_openssl_secp256r1,
        &ptls_openssl_secp384r1,
        &ptls_openssl_secp521r1,
        NULL,
    };
    ptls_ctx->key_exchanges = key_exchanges;
}

int ptls_openssl_init_sign_file(ptls_context_t *ptls_ctx, const char *privatekey_file, const char *certificate_file)
{
    int status;
    FILE *fp;
    EVP_PKEY *pkey;
    STACK_OF(X509_INFO) *pemcerts;
    size_t i, numcerts;

    /* context */
    ptls_openssl_sign_certificate_t *sign_ctx = (ptls_openssl_sign_certificate_t*)malloc(sizeof(ptls_openssl_sign_certificate_t));
    if (sign_ctx == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    memset(sign_ctx, 0, sizeof(ptls_openssl_sign_certificate_t));

    /* privatekey */
    fp = fopen(privatekey_file, "rb");
    if (fp == NULL) {
        free(sign_ctx);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    if (pkey == NULL)
    if (fp == NULL) {
        free(sign_ctx);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    status = ptls_openssl_init_sign_certificate(sign_ctx, pkey);
    if (status != 0) {
        free(sign_ctx);
        EVP_PKEY_free(pkey);
        return status;
    }
    ptls_ctx->sign_certificate = &sign_ctx->super;

    /* certificates */
    fp = fopen(certificate_file, "rb");
    if (fp == NULL) {
        free(sign_ctx);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    pemcerts = PEM_X509_INFO_read(fp, NULL, NULL, NULL);
    if (pemcerts == NULL) {
        free(sign_ctx);
        fclose(fp);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    numcerts = sk_X509_INFO_num(pemcerts);
    ptls_ctx->certificates.list = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t)*numcerts);
    ptls_ctx->certificates.count = 0;
    for( i=0; i < sk_X509_INFO_num(pemcerts); ++i )
    {
        int length;
        ptls_iovec_t *dst;
        unsigned char *p;
        X509_INFO *itmp = sk_X509_INFO_value( pemcerts, i );
        if (itmp->x509 == NULL) {
            continue;
        }
        length = i2d_X509(itmp->x509, NULL);
        if (length == 0) {
            continue;
        }
        dst = &ptls_ctx->certificates.list[ptls_ctx->certificates.count];
        ptls_ctx->certificates.count += 1;
        dst->base = (uint8_t*)malloc(length);
        p = dst->base;
        dst->len = i2d_X509(itmp->x509, &p);
    }
    sk_X509_INFO_pop_free(pemcerts, X509_INFO_free);

    /* callback internally increased reference counter */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_PKEY_free(pkey);
#endif

    return 0;
}

int ptls_openssl_init_sign_der(ptls_context_t *ptls_ctx, const ptls_iovec_t *privatekey, const ptls_iovec_t certificate[], size_t certificate_length)
{
    size_t i;
    int status;
    EVP_PKEY *pkey;
    BIO *cbio;

    /* context */
    ptls_openssl_sign_certificate_t *sign_ctx = (ptls_openssl_sign_certificate_t*)malloc(sizeof(ptls_openssl_sign_certificate_t));
    if (sign_ctx == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    memset(sign_ctx, 0, sizeof(ptls_openssl_sign_certificate_t));

    /* privatekey from DER */
    cbio = BIO_new_mem_buf(privatekey->base, privatekey->len);
    if (cbio == NULL) {
        free(sign_ctx);
        return PTLS_ERROR_NO_MEMORY;
    }
    pkey = d2i_PrivateKey_bio(cbio, NULL);
    if (pkey == NULL) {
        free(sign_ctx);
        BIO_free(cbio);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    status = ptls_openssl_init_sign_certificate(sign_ctx, pkey);
    if (status != 0) {
        free(sign_ctx);
        BIO_free(cbio);
        EVP_PKEY_free(pkey);
        return status;
    }
    ptls_ctx->sign_certificate = &sign_ctx->super;
    BIO_free(cbio);

    /* certificates already DER */
    ptls_ctx->certificates.list = (ptls_iovec_t*)calloc(certificate_length, sizeof(ptls_iovec_t));
    ptls_ctx->certificates.count = 0;
    for (i=0; i < certificate_length; ++i) {
        ptls_iovec_t *dst;
        dst = &ptls_ctx->certificates.list[ptls_ctx->certificates.count];
        ptls_ctx->certificates.count += 1;
        dst->base = (uint8_t*)malloc(certificate[i].len);
        dst->len = certificate[i].len;
        memcpy(dst->base, certificate[i].base, dst->len);
    }

    /* callback internally increased reference counter */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_PKEY_free(pkey);
#endif

    return 0;
}

void ptls_openssl_dispose_sign(ptls_context_t *ptls_ctx)
{
    size_t i;

    ptls_openssl_sign_certificate_t *sign_ctx = (ptls_openssl_sign_certificate_t*)ptls_ctx->sign_certificate;
    if (sign_ctx == NULL) {
        return;
    }
    ptls_openssl_dispose_sign_certificate(sign_ctx);

    for (i=0; i < ptls_ctx->certificates.count; ++i) {
        free(ptls_ctx->certificates.list[i].base);
    }
    free(ptls_ctx->certificates.list);
    free(sign_ctx);
}

int ptls_openssl_init_verify_file(ptls_context_t *ptls_ctx, const char *truststore_file)
{
    int status;
    X509_STORE *x509_store = NULL;

    /* context */
    ptls_openssl_verify_certificate_t *verify_ctx = (ptls_openssl_verify_certificate_t*)malloc(sizeof(ptls_openssl_verify_certificate_t));
    if (verify_ctx == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    memset(verify_ctx, 0, sizeof(ptls_openssl_verify_certificate_t));

    /* certificate */
    if (truststore_file != NULL) {
        X509_LOOKUP *x509_lookup;
        x509_store = X509_STORE_new();
        if (x509_store == NULL) {
            free(verify_ctx);
            return PTLS_ERROR_NO_MEMORY;
        }
        x509_lookup = X509_STORE_add_lookup(x509_store, X509_LOOKUP_file());
        status = X509_LOOKUP_load_file(x509_lookup, truststore_file, X509_FILETYPE_PEM);
        if (status != 1) {
            free(verify_ctx);
            X509_STORE_free(x509_store);
            return PTLS_ERROR_NO_MEMORY;
        }
    }
    status = ptls_openssl_init_verify_certificate(verify_ctx, x509_store);
    if (status != 0) {
        free(verify_ctx);
        X509_STORE_free(x509_store);
        return status;
    }
    ptls_ctx->verify_certificate = &verify_ctx->super;

    /* callback internally increased reference counter */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    if (x509_store != NULL) {
        X509_STORE_free(x509_store);
    }
#endif

    return 0;
}

int ptls_openssl_init_verify_der(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length)
{
    size_t i;
    int status;
    X509_STORE *x509_store;

    /* context */
    ptls_openssl_verify_certificate_t *verify_ctx = (ptls_openssl_verify_certificate_t*)malloc(sizeof(ptls_openssl_verify_certificate_t));
    if (verify_ctx == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    memset(verify_ctx, 0, sizeof(ptls_openssl_verify_certificate_t));

    /* certificates from DER */
    x509_store = X509_STORE_new();
    if (x509_store == NULL) {
        free(verify_ctx);
        return PTLS_ERROR_NO_MEMORY;
    }
    for (i=0; i < truststore_length; ++i) {
        const unsigned char *cert_der = truststore[i].base;
        X509 *x509 = d2i_X509(NULL, &cert_der, truststore[i].len);
        if (x509 == NULL) {
            continue;
        }
        X509_STORE_add_cert(x509_store, x509);
        X509_free(x509);
    }
    status = ptls_openssl_init_verify_certificate(verify_ctx, x509_store);
    if (status != 0) {
        free(verify_ctx);
        X509_STORE_free(x509_store);
        return status;
    }
    ptls_ctx->verify_certificate = &verify_ctx->super;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* callback internally increased reference counter */
    if (x509_store != NULL) {
        X509_STORE_free(x509_store);
    }
#endif

    return 0;
}

void ptls_openssl_dispose_verify(ptls_context_t *ptls_ctx)
{
    ptls_openssl_verify_certificate_t *verify_ctx = (ptls_openssl_verify_certificate_t*)ptls_ctx->verify_certificate;
    ptls_openssl_dispose_verify_certificate( verify_ctx );
    free(verify_ctx);
}


#else

#include "pembase64.h"

#if PTLS_HAVE_AEGIS
#include "cifra/libaegis.h"
#endif

/* import */
extern ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256,
                           ptls_minicrypto_aes256gcmsha384,
                           ptls_minicrypto_chacha20poly1305sha256;
extern ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1,
                                     ptls_minicrypto_x25519;
/* sign */
int ptls_minicrypto_init_sign_certificate(ptls_context_t *ptls_ctx, ptls_iovec_t key);
void ptls_minicrypto_dispose_sign_certificate(ptls_context_t *ptls_ctx);
/* verify */
int ptls_minicrypto_init_verify_certificate(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length);
void ptls_minicrypto_dispose_verify_certificate(ptls_context_t *ptls_ctx);


/* export */
void ptls_minicrypto_init_cipher_suites(ptls_context_t *ptls_ctx)
{
    static const ptls_cipher_suite_t *cipher_suites[] = {
        /* ciphers used with sha512 and sha384 */
#if PTLS_HAVE_AEGIS
        &ptls_minicrypto_aegis256sha512,
#endif
        &ptls_minicrypto_aes256gcmsha384,
        /* ciphers used with sha256 */
#if PTLS_HAVE_AEGIS
        &ptls_minicrypto_aegis128lsha256,
#endif
        &ptls_minicrypto_aes128gcmsha256,
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        &ptls_minicrypto_chacha20poly1305sha256,
#endif
        NULL,
    };
#if PTLS_HAVE_FUSION
    static const ptls_cipher_suite_t ptls_fusion_aes128gcmsha256 = {
        .id = PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
        .name = PTLS_CIPHER_SUITE_NAME_AES_128_GCM_SHA256,
        .aead = &ptls_fusion_aes128gcm,
        .hash = &ptls_minicrypto_sha256,
    };
    static const ptls_cipher_suite_t ptls_fusion_aes256gcmsha384 = {
        .id = PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
        .name = PTLS_CIPHER_SUITE_NAME_AES_256_GCM_SHA384,
        .aead = &ptls_fusion_aes256gcm,
        .hash = &ptls_minicrypto_sha384,
    };
    static const ptls_cipher_suite_t *cipher_suites_fusion[] = {
#if PTLS_HAVE_AEGIS
        &ptls_minicrypto_aegis256sha512,
#endif
        &ptls_fusion_aes256gcmsha384,
#if PTLS_HAVE_AEGIS
        &ptlsminicrypto_aegis128lsha256,
#endif
        &ptls_fusion_aes128gcmsha256,
        &ptls_minicrypto_chacha20poly1305sha256,
        NULL,
    };
    if (ptls_fusion_is_supported_by_cpu()) {
        ptls_ctx->cipher_suites = cipher_suites_fusion;
        return;
    }
#endif
    ptls_ctx->cipher_suites = cipher_suites;
}

void ptls_minicrypto_init_key_exchanges(ptls_context_t *ptls_ctx)
{
    static const ptls_key_exchange_algorithm_t *key_exchanges[] = {
        &ptls_minicrypto_secp256r1,
        &ptls_minicrypto_x25519,
        NULL,
    };
    ptls_ctx->key_exchanges = key_exchanges;
}

#define PTLS_MAX_CERTS_IN_CONTEXT 16
int ptls_minicrypto_init_sign_file(ptls_context_t *ptls_ctx, const char *privatekey_file, const char *certificate_file)
{
    ptls_iovec_t privatekey_vec = {0};
    ptls_iovec_t certificates_vecs[PTLS_MAX_CERTS_IN_CONTEXT];
    size_t nb_keys = 0, nb_certs = 0;

    /* load */
    int ret = ptls_load_pem_objects(privatekey_file, "PRIVATE KEY", &privatekey_vec, 1, &nb_keys);
    if (ret != 0)
        return ret;
    if (nb_keys != 1) {
        ptls_clear_memory(privatekey_vec.base, privatekey_vec.len);
        free(privatekey_vec.base);
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    ret = ptls_load_pem_objects(certificate_file, "CERTIFICATE", certificates_vecs, PTLS_MAX_CERTS_IN_CONTEXT, &nb_certs);
    if (ret != 0) {
        free(privatekey_vec.base);
        return PTLS_ERROR_PEM_LABEL_NOT_FOUND;
    }

    /* setup */
    ret = ptls_minicrypto_init_sign_der(ptls_ctx, &privatekey_vec, certificates_vecs, nb_certs);

    /* cleanup */
    if (privatekey_vec.base) {
        ptls_clear_memory(privatekey_vec.base, privatekey_vec.len);
        free(privatekey_vec.base);
    }
    return ret;
}

int ptls_minicrypto_init_sign_der(ptls_context_t *ptls_ctx, const ptls_iovec_t *privatekey, const ptls_iovec_t certificate[], size_t certificate_length)
{
    size_t i;
    int ret = ptls_minicrypto_init_sign_certificate(ptls_ctx, *privatekey);
    if (ret != 0) {
        return ret;
    }

    ptls_ctx->certificates.list = (ptls_iovec_t*)calloc(certificate_length, sizeof(ptls_iovec_t));
    if (ptls_ctx->certificates.list == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    ptls_ctx->certificates.count = 0;
    for (i=0; i < certificate_length; ++i) {
        ptls_iovec_t *dst;
        dst = &ptls_ctx->certificates.list[ptls_ctx->certificates.count];
        ptls_ctx->certificates.count += 1;
        dst->base = (uint8_t*)malloc(certificate[i].len);
        dst->len = certificate[i].len;
        memcpy(dst->base, certificate[i].base, dst->len);
    }
    return 0;
}

void ptls_minicrypto_dispose_sign(ptls_context_t *ptls_ctx)
{
    size_t i;
    ptls_minicrypto_dispose_sign_certificate(ptls_ctx);

    for (i=0; i < ptls_ctx->certificates.count; ++i) {
        free(ptls_ctx->certificates.list[i].base);
    }
    free(ptls_ctx->certificates.list);
}

#define PTLS_MAX_TRUSTCA_IN_CONTEXT 256
int ptls_minicrypto_init_verify_file(ptls_context_t *ptls_ctx, const char *truststore_file)
{
    /* load */
    ptls_iovec_t truststore_vecs[PTLS_MAX_TRUSTCA_IN_CONTEXT];
    size_t i, nb_certs = 0;
    int ret = ptls_load_pem_objects(truststore_file, "CERTIFICATE", truststore_vecs, PTLS_MAX_TRUSTCA_IN_CONTEXT, &nb_certs);
    if (ret != 0) {
        return PTLS_ERROR_PEM_LABEL_NOT_FOUND;
    }

    /* setup */
    ret = ptls_minicrypto_init_verify_der(ptls_ctx, truststore_vecs, nb_certs);

    /* cleanup */
    for (i=0; i < ptls_ctx->certificates.count; ++i) {
        free(truststore_vecs[i].base);
    }
    return ret;
}

int ptls_minicrypto_init_verify_der(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length)
{
    return ptls_minicrypto_init_verify_certificate(ptls_ctx, truststore, truststore_length);
}

void ptls_minicrypto_dispose_verify(ptls_context_t *ptls_ctx)
{
    ptls_minicrypto_dispose_verify_certificate(ptls_ctx);
}

#endif
