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
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "picotls.h"
#include "picotls_openssl.h"

struct st_ptls_openssl_server_context_t {
    char *name;
    EVP_PKEY_CTX *sign_ctx;
    size_t num_certs;
    ptls_iovec_t certs[1];
};

struct st_ptls_openssl_context_t {
    ptls_context_t super;
    struct {
        struct st_ptls_openssl_server_context_t **entries;
        size_t count;
    } servers;
};

static void random_bytes(void *buf, size_t len)
{
    RAND_bytes(buf, (int)len);
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
    if ((bn_ctx = BN_CTX_new()) != NULL) {
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

static int rsapss_sign(void *data, ptls_iovec_t hash)
{
    // EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING)
    EVP_PKEY_sign((EVP_PKEY_CTX *)data, NULL, 0, hash.base, hash.len);
    return 0;
}

static ptls_aead_context_t *aead_aes128gcm_create(const uint8_t *key)
{
    return NULL;
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

static int on_client_hello(ptls_t *tls, uint16_t *sign_algorithm,
                           int (**signer)(void *sign_ctx, ptls_iovec_t *output, ptls_iovec_t input), void *signer_data,
                           ptls_iovec_t **certs, size_t *num_certs, ptls_iovec_t server_name, const uint16_t *signature_algorithms,
                           size_t num_signature_algorithms)
{
    return 1;
}

static void free_server_context(struct st_ptls_openssl_server_context_t *ctx)
{
    size_t i;

    free(ctx->name);
    EVP_PKEY_CTX_free(ctx->sign_ctx);
    for (i = 0; i != ctx->num_certs; ++i)
        free(ctx->certs[i].base);
    free(ctx);
}

ptls_openssl_context_t *ptls_openssl_context_new(void)
{
    ptls_openssl_context_t *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return NULL;

    ctx->super = (ptls_context_t){&ptls_openssl_crypto, {on_client_hello}};
    return ctx;
}

void ptls_openssl_context_free(ptls_openssl_context_t *ctx)
{
    size_t i;

    for (i = 0; i != ctx->servers.count; ++i) {
        free_server_context(ctx->servers.entries[i]);
    }
    free(ctx->servers.entries);
    free(ctx);
}

ptls_context_t *ptls_openssl_context_get_context(ptls_openssl_context_t *ctx)
{
    assert(ctx->servers.count != 0 && !"register_server must be invoked more than once");
    return &ctx->super;
}

int ptls_openssl_register_server(ptls_openssl_context_t *ctx, const char *server_name, EVP_PKEY *key, STACK_OF(X509) * certs)
{
    struct st_ptls_openssl_server_context_t *slot, **new_entries;
    size_t i;
    int ret;

    if ((slot = malloc(offsetof(struct st_ptls_openssl_server_context_t, certs) + sizeof(slot->certs[0]) * sk_X509_num(certs))) ==
        NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }

    *slot = (struct st_ptls_openssl_server_context_t){};
    if ((slot->name = strdup(server_name)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }

    if ((slot->sign_ctx = EVP_PKEY_CTX_new(key, NULL)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    EVP_PKEY_CTX_set_rsa_padding(slot->sign_ctx, RSA_PKCS1_PSS_PADDING);
    slot->num_certs = sk_X509_num(certs);
    for (i = 0; i != slot->num_certs; ++i) {
        X509 *cert = sk_X509_value(certs, (int)i);
        int len = i2d_X509(cert, NULL);
        if (len < 0) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
        if ((slot->certs[i].base = malloc(len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Error;
        }
        if (i2d_X509(cert, (unsigned char **)&slot->certs[i].base) != len) {
            ret = PTLS_ERROR_LIBRARY;
            goto Error;
        }
        slot->certs[i].len = len;
    }

    if ((new_entries = realloc(ctx->servers.entries, sizeof(ctx->servers.entries[0]) * (ctx->servers.count + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    ctx->servers.entries = new_entries;
    ctx->servers.entries[ctx->servers.count++] = slot;

    return 0;

Error:
    if (slot != NULL)
        free_server_context(slot);
    return ret;
}

static ptls_key_exchange_algorithm_t key_exchanges[] = {{PTLS_GROUP_SECP256R1, secp256r1_key_exchange}, {UINT16_MAX}};
ptls_aead_algorithm_t ptls_openssl_aes128gcm = {16, 16, aead_aes128gcm_create};
ptls_hash_algorithm_t ptls_openssl_sha256 = {64, 32, sha256_create};
static ptls_cipher_suite_t cipher_suites[] = {{PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_openssl_aes128gcm, &ptls_openssl_sha256},
                                              {UINT16_MAX}};

ptls_crypto_t ptls_openssl_crypto = {random_bytes, key_exchanges, cipher_suites};
