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
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include "picotls.h"
#include "picotls/openssl.h"

#define OPENSSL_1_0_API (OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER))

#if OPENSSL_1_0_API

#define EVP_PKEY_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_EVP_PKEY)
#define X509_STORE_up_ref(p) CRYPTO_add(&(p)->references, 1, CRYPTO_LOCK_X509_STORE)

#endif

void ptls_openssl_random_bytes(void *buf, size_t len)
{
    RAND_bytes(buf, (int)len);
}

static int eckey_is_on_group(EVP_PKEY *pkey, int nid)
{
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(pkey);
    int ret = 0;

    if (eckey != NULL) {
        ret = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey)) == nid;
        EC_KEY_free(eckey);
    }

    return ret;
}

static EC_KEY *ecdh_gerenate_key(EC_GROUP *group)
{
    EC_KEY *key;

    if ((key = EC_KEY_new()) == NULL)
        return NULL;
    if (!EC_KEY_set_group(key, group) || !EC_KEY_generate_key(key)) {
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

static int ecdh_calc_secret(ptls_iovec_t *out, EC_GROUP *group, EC_KEY *privkey, EC_POINT *peer_point)
{
    ptls_iovec_t secret;
    int ret;

    secret.len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret.base = malloc(secret.len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (ECDH_compute_key(secret.base, secret.len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }
    ret = 0;

Exit:
    if (ret == 0) {
        *out = secret;
    } else {
        free(secret.base);
        *out = (ptls_iovec_t){NULL};
    }
    return ret;
}

static EC_POINT *x9_62_decode_point(EC_GROUP *group, ptls_iovec_t vec, BN_CTX *bn_ctx)
{
    EC_POINT *point = NULL;

    if ((point = EC_POINT_new(group)) == NULL)
        return NULL;
    if (!EC_POINT_oct2point(group, point, vec.base, vec.len, bn_ctx)) {
        EC_POINT_free(point);
        return NULL;
    }

    return point;
}

static ptls_iovec_t x9_62_encode_point(EC_GROUP *group, const EC_POINT *point, BN_CTX *bn_ctx)
{
    ptls_iovec_t vec;

    if ((vec.len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx)) == 0)
        return (ptls_iovec_t){NULL};
    if ((vec.base = malloc(vec.len)) == NULL)
        return (ptls_iovec_t){NULL};
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, vec.base, vec.len, bn_ctx) != vec.len) {
        free(vec.base);
        return (ptls_iovec_t){NULL};
    }

    return vec;
}

struct st_x9_62_keyex_context_t {
    ptls_key_exchange_context_t super;
    BN_CTX *bn_ctx;
    EC_GROUP *group;
    EC_KEY *privkey;
    ptls_iovec_t pubkey;
};

static void x9_62_free_context(struct st_x9_62_keyex_context_t *ctx)
{
    free(ctx->pubkey.base);
    if (ctx->privkey != NULL)
        EC_KEY_free(ctx->privkey);
    if (ctx->group != NULL)
        EC_GROUP_free(ctx->group);
    if (ctx->bn_ctx != NULL)
        BN_CTX_free(ctx->bn_ctx);
    free(ctx);
}

static int x9_62_on_exchange(ptls_key_exchange_context_t *_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x9_62_keyex_context_t *ctx = (struct st_x9_62_keyex_context_t *)_ctx;
    EC_POINT *peer_point = NULL;
    int ret;

    if ((peer_point = x9_62_decode_point(ctx->group, peerkey, ctx->bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    if ((ret = ecdh_calc_secret(secret, ctx->group, ctx->privkey, peer_point)) != 0)
        goto Exit;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    x9_62_free_context(ctx);
    return ret;
}

static int x9_62_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey, int nid)
{
    struct st_x9_62_keyex_context_t *ctx = NULL;
    int ret;

    if ((ctx = (struct st_x9_62_keyex_context_t *)malloc(sizeof(*ctx))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *ctx = (struct st_x9_62_keyex_context_t){{x9_62_on_exchange}};

    if ((ctx->bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((ctx->group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ctx->privkey = ecdh_gerenate_key(ctx->group)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    if ((ctx->pubkey = x9_62_encode_point(ctx->group, EC_KEY_get0_public_key(ctx->privkey), ctx->bn_ctx)).base == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    *pubkey = ctx->pubkey;
    ret = 0;

Exit:
    if (ret == 0) {
        *_ctx = &ctx->super;
    } else {
        if (ctx != NULL)
            x9_62_free_context(ctx);
        *_ctx = NULL;
        *pubkey = (ptls_iovec_t){NULL};
    }

    return ret;
}

static int secp256r1_create_key_exchange(ptls_key_exchange_context_t **ctx, ptls_iovec_t *pubkey)
{
    return x9_62_create_key_exchange(ctx, pubkey, NID_X9_62_prime256v1);
}

static int x9_62_key_exchange(EC_GROUP *group, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey, BN_CTX *bn_ctx)
{
    EC_POINT *peer_point = NULL;
    EC_KEY *privkey = NULL;
    int ret;

    *pubkey = (ptls_iovec_t){NULL};
    *secret = (ptls_iovec_t){NULL};

    /* decode peer key */
    if ((peer_point = x9_62_decode_point(group, peerkey, bn_ctx)) == NULL) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    /* create private key */
    if ((privkey = ecdh_gerenate_key(group)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* encode public key */
    if ((*pubkey = x9_62_encode_point(group, EC_KEY_get0_public_key(privkey), bn_ctx)).base == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* calc secret */
    secret->len = (EC_GROUP_get_degree(group) + 7) / 8;
    if ((secret->base = malloc(secret->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* ecdh! */
    if (ECDH_compute_key(secret->base, secret->len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }

    ret = 0;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    if (privkey != NULL)
        EC_KEY_free(privkey);
    if (ret != 0) {
        free(pubkey->base);
        *pubkey = (ptls_iovec_t){NULL};
        free(secret->base);
        *secret = (ptls_iovec_t){NULL};
    }
    return ret;
}

static int secp_key_exchange(int nid, ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    EC_GROUP *group = NULL;
    BN_CTX *bn_ctx = NULL;
    int ret;

    if ((group = EC_GROUP_new_by_curve_name(nid)) == NULL) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((bn_ctx = BN_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    ret = x9_62_key_exchange(group, pubkey, secret, peerkey, bn_ctx);

Exit:
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    return ret;
}

static int secp256r1_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    return secp_key_exchange(NID_X9_62_prime256v1, pubkey, secret, peerkey);
}

static int rsapss_sign(void *data, ptls_iovec_t *output, ptls_iovec_t input)
{
    EVP_PKEY *key = data;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx;
    int ret;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestSignInit(ctx, &pkey_ctx, EVP_sha256(), NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestSignUpdate(ctx, input.base, input.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestSignFinal(ctx, NULL, &output->len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((output->base = malloc(output->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestSignFinal(ctx, output->base, &output->len) != 1) {
        free(output->base);
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    ret = 0;
Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    return ret;
}

struct aead_crypto_context_t {
    ptls_aead_context_t super;
    EVP_CIPHER_CTX *evp_ctx;
    size_t tag_size;
};

static void aead_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;

    if (ctx->evp_ctx != NULL)
        EVP_CIPHER_CTX_free(ctx->evp_ctx);
}

static int aead_do_encrypt(ptls_aead_context_t *_ctx, void *_output, size_t *outlen, const void *input, size_t inlen,
                           const void *iv, uint8_t enc_content_type)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output;
    int blocklen;

    *outlen = 0;

    /* FIXME for performance, preserve the expanded key instead of the raw key */
    if (!EVP_EncryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv))
        return PTLS_ERROR_LIBRARY;
    if (!EVP_EncryptUpdate(ctx->evp_ctx, output, &blocklen, input, (int)inlen))
        return PTLS_ERROR_LIBRARY;
    *outlen += blocklen;
    if (!EVP_EncryptUpdate(ctx->evp_ctx, output + *outlen, &blocklen, &enc_content_type, 1))
        return PTLS_ERROR_LIBRARY;
    *outlen += blocklen;
    if (!EVP_EncryptFinal_ex(ctx->evp_ctx, output + *outlen, &blocklen))
        return PTLS_ERROR_LIBRARY;
    *outlen += blocklen;
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_GET_TAG, (int)ctx->tag_size, output + *outlen))
        return PTLS_ERROR_LIBRARY;
    *outlen += ctx->tag_size;

    return 0;
}

static int aead_do_decrypt(ptls_aead_context_t *_ctx, void *_output, size_t *outlen, const void *input, size_t inlen,
                           const void *iv, uint8_t unused)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    uint8_t *output = _output;
    int blocklen;

    *outlen = 0;

    if (inlen < ctx->tag_size)
        return PTLS_ALERT_BAD_RECORD_MAC;

    if (!EVP_DecryptInit_ex(ctx->evp_ctx, NULL, NULL, NULL, iv))
        return PTLS_ERROR_LIBRARY;
    if (!EVP_DecryptUpdate(ctx->evp_ctx, output, &blocklen, input, (int)(inlen - ctx->tag_size)))
        return PTLS_ERROR_LIBRARY;
    *outlen += blocklen;
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_TAG, (int)ctx->tag_size,
                             (void *)((uint8_t *)input + inlen - ctx->tag_size)))
        return PTLS_ERROR_LIBRARY;
    if (!EVP_DecryptFinal_ex(ctx->evp_ctx, output + *outlen, &blocklen))
        return PTLS_ALERT_BAD_RECORD_MAC;
    *outlen += blocklen;

    return 0;
}

static int aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, const EVP_CIPHER *cipher, size_t tag_size)
{
    struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *)_ctx;
    int ret;

    ctx->super.dispose_crypto = aead_dispose_crypto;
    ctx->super.do_transform = is_enc ? aead_do_encrypt : aead_do_decrypt;
    ctx->evp_ctx = NULL;
    ctx->tag_size = tag_size;

    if ((ctx->evp_ctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    if (is_enc) {
        if (!EVP_EncryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    } else {
        if (!EVP_DecryptInit_ex(ctx->evp_ctx, cipher, NULL, key, NULL)) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx->evp_ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ctx->super.algo->iv_size, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Error;
    }

    return 0;

Error:
    aead_dispose_crypto(&ctx->super);
    return ret;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_setup_crypto(ctx, is_enc, key, EVP_aes_128_gcm(), 16);
}

struct sha256_context_t {
    ptls_hash_context_t super;
    SHA256_CTX ctx;
};

static void sha256_update(ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct sha256_context_t *ctx = (struct sha256_context_t *)_ctx;

    SHA256_Update(&ctx->ctx, src, len);
}

static void sha256_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    struct sha256_context_t *ctx = (struct sha256_context_t *)_ctx;

    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        SHA256_CTX copy = ctx->ctx;
        SHA256_Final(md, &copy);
        ptls_clear_memory(&copy, sizeof(copy));
        return;
    }

    if (md != NULL)
        SHA256_Final(md, &ctx->ctx);

    switch (mode) {
    case PTLS_HASH_FINAL_MODE_FREE:
        ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));
        free(ctx);
        break;
    case PTLS_HASH_FINAL_MODE_RESET:
        SHA256_Init(&ctx->ctx);
        break;
    default:
        assert(!"FIXME");
        break;
    }
}

static ptls_hash_context_t *sha256_create(void)
{
    struct sha256_context_t *ctx;

    if ((ctx = malloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->super = (ptls_hash_context_t){sha256_update, sha256_final};
    SHA256_Init(&ctx->ctx);
    return &ctx->super;
}

static int ascii_tolower(int ch)
{
    return ('A' <= ch && ch <= 'Z') ? ch + 0x20 : ch;
}

static int ascii_streq_caseless(ptls_iovec_t x, ptls_iovec_t y)
{
    size_t i;
    if (x.len != y.len)
        return 0;
    for (i = 0; i != x.len; ++i)
        if (ascii_tolower(x.base[i]) != ascii_tolower(y.base[i]))
            return 0;
    return 0;
}

static uint16_t select_compatible_signature_algorithm(EVP_PKEY *key, const uint16_t *signature_algorithms,
                                                      size_t num_signature_algorithms)
{
    size_t i;

    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        /* Section 4.4.2: RSA signatures MUST use an RSASSA-PSS algorithm, regardless of whether RSASSA-PKCS1-v1_5 algorithms appear
         * in "signature_algorithms". */
        for (i = 0; i != num_signature_algorithms; ++i)
            if (signature_algorithms[i] == PTLS_SIGNATURE_RSA_PSS_SHA256)
                return PTLS_SIGNATURE_RSA_PSS_SHA256;
        break;
    case EVP_PKEY_EC:
        for (i = 0; i != num_signature_algorithms; ++i)
            if (signature_algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
                return PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
        break;
    default:
        assert(!"logic flaw");
        break;
    }

    return UINT16_MAX;
}

static int lookup_certificate(ptls_lookup_certificate_t *_self, ptls_t *tls, uint16_t *sign_algorithm,
                              int (**signer)(void *sign_ctx, ptls_iovec_t *output, ptls_iovec_t input), void **signer_data,
                              ptls_iovec_t **certs, size_t *num_certs, const char *server_name,
                              const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
    ptls_openssl_lookup_certificate_t *self = (ptls_openssl_lookup_certificate_t *)_self;
    struct st_ptls_openssl_identity_t *identity;

    if (self->count == 0)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    if (server_name != NULL) {
        size_t i, server_name_len = strlen(server_name);
        for (i = 0; i != self->count; ++i) {
            identity = self->identities[i];
            if (ascii_streq_caseless(ptls_iovec_init(server_name, server_name_len), identity->name) &&
                (*sign_algorithm = select_compatible_signature_algorithm(identity->key, signature_algorithms,
                                                                         num_signature_algorithms)) != UINT16_MAX)
                goto Found;
        }
    }
    /* not found, use the first one, if the signing algorithm matches */
    identity = self->identities[0];
    if ((*sign_algorithm = select_compatible_signature_algorithm(identity->key, signature_algorithms, num_signature_algorithms)) ==
        UINT16_MAX)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

Found:
    /* setup the rest */
    *signer = rsapss_sign;
    *signer_data = identity->key;
    *certs = identity->certs;
    *num_certs = identity->num_certs;

    return 0;
}

static X509 *to_x509(ptls_iovec_t vec)
{
    const uint8_t *p = vec.base;
    return d2i_X509(NULL, &p, vec.len);
}

static int verify_sign(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature)
{
    EVP_PKEY *key = verify_ctx;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx;
    int ret = 0;

    if (data.base == NULL)
        goto Exit;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestVerifyUpdate(ctx, data.base, data.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestVerifyFinal(ctx, signature.base, signature.len) != 1) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = 0;

Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    return ret;
}

static void free_identity(struct st_ptls_openssl_identity_t *identity)
{
    size_t i;

    free(identity->name.base);
    if (identity->key != NULL)
        EVP_PKEY_free(identity->key);
    for (i = 0; i != identity->num_certs; ++i)
        free(identity->certs[i].base);
    free(identity);
}

void ptls_openssl_init_lookup_certificate(ptls_openssl_lookup_certificate_t *self)
{
    *self = (ptls_openssl_lookup_certificate_t){{lookup_certificate}};
}

void ptls_openssl_dispose_lookup_certificate(ptls_openssl_lookup_certificate_t *self)
{
    size_t i;
    for (i = 0; i != self->count; ++i)
        free_identity(self->identities[i]);
    free(self->identities);
    free(self);
}

int ptls_openssl_lookup_certificate_add_identity(ptls_openssl_lookup_certificate_t *self, const char *server_name, EVP_PKEY *key,
                                                 STACK_OF(X509) * certs)
{
    struct st_ptls_openssl_identity_t *slot, **new_identities;
    size_t i;
    int ret;

    if ((slot = malloc(offsetof(struct st_ptls_openssl_identity_t, certs) + sizeof(slot->certs[0]) * sk_X509_num(certs))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }

    *slot = (struct st_ptls_openssl_identity_t){{NULL}};
    if ((slot->name.base = (uint8_t *)strdup(server_name)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    slot->name.len = strlen(server_name);

    EVP_PKEY_up_ref(key);
    slot->key = key;
    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        break;
    case EVP_PKEY_EC:
        if (!eckey_is_on_group(key, NID_X9_62_prime256v1)) {
            ret = PTLS_ERROR_INCOMPATIBLE_KEY;
            goto Error;
        }
        break;
    default:
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
        goto Error;
    }

    slot->num_certs = sk_X509_num(certs);
    for (i = 0; i != slot->num_certs; ++i) {
        X509 *cert = sk_X509_value(certs, (int)i);
        int len = i2d_X509(cert, NULL);
        if (len <= 0) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
        if ((slot->certs[i].base = malloc(len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Error;
        }
        unsigned char *p = slot->certs[i].base;
        if (i2d_X509(cert, &p) != len) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
        slot->certs[i].len = len;
    }

    if ((new_identities = realloc(self->identities, sizeof(self->identities[0]) * (self->count + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    self->identities = new_identities;
    self->identities[self->count++] = slot;

    return 0;

Error:
    if (slot != NULL)
        free_identity(slot);
    return ret;
}

static int verify_certificate(ptls_verify_certificate_t *_self, ptls_t *tls, int (**verifier)(void *, ptls_iovec_t, ptls_iovec_t),
                              void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    ptls_openssl_verify_certificate_t *self = (ptls_openssl_verify_certificate_t *)_self;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = NULL;
    X509_STORE_CTX *verify_ctx = NULL;
    int ret = 0;

    assert(num_certs != 0);

    if ((cert = to_x509(certs[0])) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }

    if (self->cert_store != NULL) {
        size_t i;
        for (i = 1; i != num_certs; ++i) {
            X509 *interm = to_x509(certs[i]);
            if (interm == NULL) {
                ret = PTLS_ALERT_BAD_CERTIFICATE;
                goto Exit;
            }
        }
        if ((verify_ctx = X509_STORE_CTX_new()) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        if (X509_STORE_CTX_init(verify_ctx, self->cert_store, cert, chain) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        X509_STORE_CTX_set_purpose(verify_ctx, X509_PURPOSE_SSL_CLIENT);
        if (X509_verify_cert(verify_ctx) == 1) {
            ret = 0;
        } else {
            switch (X509_STORE_CTX_get_error(verify_ctx)) {
            case X509_V_ERR_OUT_OF_MEM:
                ret = PTLS_ERROR_NO_MEMORY;
                goto Exit;
            case X509_V_ERR_CERT_REVOKED:
                ret = PTLS_ALERT_CERTIFICATE_REVOKED;
                goto Exit;
            case X509_V_ERR_CERT_HAS_EXPIRED:
                ret = PTLS_ALERT_CERTIFICATE_EXPIRED;
                goto Exit;
            default:
                ret = PTLS_ALERT_CERTIFICATE_UNKNOWN;
                goto Exit;
            }
        }
    }

    if ((*verify_data = X509_get_pubkey(cert)) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }
    *verifier = verify_sign;

Exit:
    if (verify_ctx != NULL)
        X509_STORE_CTX_free(verify_ctx);
    if (chain != NULL)
        sk_X509_free(chain);
    if (cert != NULL)
        X509_free(cert);
    return ret;
}

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store)
{
    *self = (ptls_openssl_verify_certificate_t){{verify_certificate}};

    if (store != NULL) {
        X509_STORE_up_ref(store);
        self->cert_store = store;
    } else {
        X509_LOOKUP *lookup;
        if ((self->cert_store = X509_STORE_new()) == NULL)
            return -1;
        if ((lookup = X509_STORE_add_lookup(self->cert_store, X509_LOOKUP_file())) == NULL)
            return -1;
        X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
        if ((lookup = X509_STORE_add_lookup(self->cert_store, X509_LOOKUP_hash_dir())) == NULL)
            return -1;
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

    return 0;
}

void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self)
{
    X509_STORE_free(self->cert_store);
    free(self);
}

ptls_key_exchange_algorithm_t ptls_openssl_secp256r1 = {PTLS_GROUP_SECP256R1, secp256r1_create_key_exchange,
                                                        secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_openssl_key_exchanges[] = {&ptls_openssl_secp256r1, NULL};
ptls_aead_algorithm_t ptls_openssl_aes128gcm = {16, 12, sizeof(struct aead_crypto_context_t), aead_aes128gcm_setup_crypto};
ptls_hash_algorithm_t ptls_openssl_sha256 = {64, 32, sha256_create};
ptls_cipher_suite_t ptls_openssl_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_openssl_aes128gcm,
                                                    &ptls_openssl_sha256};
ptls_cipher_suite_t *ptls_openssl_cipher_suites[] = {&ptls_openssl_aes128gcmsha256, NULL};
