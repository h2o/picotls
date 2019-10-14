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

#ifndef _WINDOWS
/* This module is only defined for windows.
 * It is an implementation of the main crypto algorithms
 * using windows crypto libraries */

int ptls_bcrypt_init()
{
    return -1;
}

void ptlc_bcrypt_dispose()
{
}

#else

#include "wincompat.h"
#include <bcrypt.h>
#include "picotls.h"

/**
 * Initialize the brcrypt libraries, creates the
 * required common variables, etc. */
int ptls_bcrypt_init()
{
    return -1;
}

/**
 * Clear the initialization of the bcrypt libraries */

void ptlc_bcrypt_dispose()
{
}

/**
 * Random number generation */

void ptls_bcrypt_random_bytes(void *buf, size_t len)
{
    /* TODO: Crypto gen random */
}

/**
 * a symmetric cipher
 *
typedef const struct st_ptls_cipher_algorithm_t {
    const char *name;
    size_t key_size;
    size_t block_size;
    size_t iv_size;
    size_t context_size;
    int (*setup_crypto)(ptls_cipher_context_t *ctx, int is_enc, const void *key);
} ptls_cipher_algorithm_t;
*/

/**
 * context of a symmetric cipher
 * the "algo" field must not be altered by crypto bindings.

typedef struct st_ptls_cipher_context_t {
    const struct st_ptls_cipher_algorithm_t *algo;
    void (*do_dispose)(struct st_ptls_cipher_context_t *ctx);
    void (*do_init)(struct st_ptls_cipher_context_t *ctx, const void *iv);
    void (*do_transform)(struct st_ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
} ptls_cipher_context_t;

*/

struct ptls_bcrypt_symmetric_param_t {
    HANDLE hKey;
    DWORD dwFlags;
    ULONG cbKeyObject;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t *key_object;
    int is_enc;
};

struct ptls_bcrypt_symmetric_context_t {
    ptls_cipher_context_t super;
    struct ptls_bcrypt_symmetric_param_t bctx;
};

static void ptls_bcrypt_cipher_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    /* Copy the IV to inside structure */
    memcpy(ctx->bctx.iv, iv, ctx->super.algo->iv_size);
}

static void ptls_bcrypt_cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;

    if (ctx->bctx.hKey != NULL) {
        (void)BCryptDestroyKey(ctx->bctx.hKey);
    }

    if (ctx->bctx.key_object != NULL) {
        free(ctx->bctx.key_object);
    }

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));
}

static void ptls_bcrypt_cipher_transform_ecb(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    ULONG cbResult;
    NTSTATUS ret;

    assert((len % ctx->super.algo->block_size) == 0);

    /* Call the encryption */
    if (ctx->bctx.is_enc) {
        ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)len, NULL, NULL, 0, output, (ULONG)len, &cbResult, 0);
    } else {
        ret = BCryptDecrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)len, NULL, NULL, 0, output, (ULONG)len, &cbResult, 0);
    }

    assert(BCRYPT_SUCCESS(ret));
}

static void ptls_bcrypt_cipher_transform_ctr(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    ULONG cbResult;
    NTSTATUS ret;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t eiv[PTLS_MAX_IV_SIZE];
    size_t iv_size = _ctx->algo->iv_size;
    size_t i;
    uint64_t seq = 0;
    size_t processed = 0;
    uint8_t const *v_in = input;
    uint8_t *v_out = output;

    assert(ctx->super.algo->block_size <= PTLS_MAX_IV_SIZE);

    while (processed < len) {
        /* Build the next iv block */
        const uint8_t *s = ctx->bctx.iv;
        uint8_t *d = iv;
        for (i = iv_size - 8; i != 0; --i)
            *d++ = *s++;
        i = 64;
        do {
            i -= 8;
            *d++ = *s++ ^ (uint8_t)(seq >> i);
        } while (i != 0);

        ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)iv, (ULONG)ctx->super.algo->block_size, NULL, NULL, 0, eiv,
                            (ULONG)(ULONG)ctx->super.algo->block_size, &cbResult, 0);
        assert(BCRYPT_SUCCESS(ret));

        for (i = 0; processed < len && i < ctx->super.algo->block_size; i++, processed++) {
            v_out[processed] = v_in[processed] ^ eiv[i];
        }
    }
}

static int ptls_bcrypt_cipher_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, wchar_t const *bcrypt_name,
                                           int is_ctr)
{
    struct ptls_bcrypt_symmetric_context_t *ctx = (struct ptls_bcrypt_symmetric_context_t *)_ctx;
    HANDLE hAlgorithm = NULL;
    NTSTATUS ret;

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));

    ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

    if (BCRYPT_SUCCESS(ret)) {
        DWORD ko_size = 0;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ko_size, (ULONG)sizeof(ko_size), &cbResult, 0);

        if (BCRYPT_SUCCESS(ret)) {
            ctx->bctx.key_object = (uint8_t *)malloc(ko_size);
            if (ctx->bctx.key_object == NULL) {
                ret = STATUS_NO_MEMORY;
            } else {
                ctx->bctx.cbKeyObject = ko_size;
            }
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptGenerateSymmetricKey(hAlgorithm, &ctx->bctx.hKey, ctx->bctx.key_object, ctx->bctx.cbKeyObject, (PUCHAR)key,
                                         (ULONG)ctx->super.algo->key_size, 0);
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {

        ctx->super.do_dispose = ptls_bcrypt_cipher_dispose;
        ctx->super.do_init = ptls_bcrypt_cipher_init;
        if (is_ctr) {
            ctx->super.do_transform = ptls_bcrypt_cipher_transform_ctr;
        } else {
            ctx->super.do_transform = ptls_bcrypt_cipher_transform_ecb;
        }
        ctx->bctx.is_enc = is_enc;
        return 0;
    } else {
        ptls_bcrypt_cipher_dispose(_ctx);
        return PTLS_ERROR_LIBRARY;
    }
}

static int ptls_bcrypt_cipher_setup_crypto_aes_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    return ptls_bcrypt_cipher_setup_crypto(_ctx, is_enc, key, BCRYPT_AES_ALGORITHM, 0);
}

static int ptls_bcrypt_cipher_setup_crypto_aes_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    return ptls_bcrypt_cipher_setup_crypto(_ctx, is_enc, key, BCRYPT_AES_ALGORITHM, 1);
}

struct ptls_bcrypt_aead_param_t {
    HANDLE hKey;
    ULONG cbKeyObject;
    uint8_t *key_object;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t tag[PTLS_MAX_DIGEST_SIZE];
    uint64_t nonce;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead_params;
};

struct ptls_bcrypt_aead_context_t {
    struct st_ptls_aead_context_t super;
    struct ptls_bcrypt_aead_param_t bctx;
};

static void ptls_bcrypt_aead_dispose_crypto(struct st_ptls_aead_context_t *_ctx)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;

    if (ctx->bctx.hKey != NULL) {
        (void)BCryptDestroyKey(ctx->bctx.hKey);
    }

    if (ctx->bctx.key_object != NULL) {
        free(ctx->bctx.key_object);
    }

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_aead_param_t));
}

static void ptls_bcrypt_aead_do_encrypt_init(struct st_ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;

    /* Save a copy of the IV*/
    memcpy(ctx->bctx.iv, iv, ctx->super.algo->iv_size);
    /* Auth tag to NULL */
    memset(ctx->bctx.tag, 0, sizeof(ctx->super.algo->tag_size));

    /* pPaddingInfo must point to BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. */
    BCRYPT_INIT_AUTH_MODE_INFO(ctx->bctx.aead_params);
    /* TODO: find clarity on handling of nonce */
    ctx->bctx.nonce = 0;
    ctx->bctx.aead_params.pbNonce = (PUCHAR)&ctx->bctx.nonce;
    ctx->bctx.aead_params.cbNonce = (ULONG)sizeof(ctx->bctx.nonce);
    ctx->bctx.aead_params.pbAuthData = (PUCHAR)aad;
    ctx->bctx.aead_params.cbAuthData = (ULONG)aadlen;
    ctx->bctx.aead_params.pbTag = (PUCHAR)ctx->bctx.tag;
    ctx->bctx.aead_params.cbTag = (ULONG)ctx->super.algo->tag_size;
}

static size_t ptls_bcrypt_aead_do_encrypt_update(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    size_t outlenMax = inlen;
    ULONG cbResult = 0;
    NTSTATUS ret;

    /* Call the decryption */
    ret = BCryptEncrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)inlen, (void *)&ctx->bctx.aead_params, ctx->bctx.iv,
                        (ULONG)ctx->super.algo->iv_size, output, (ULONG)outlenMax, &cbResult,
                        BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG | BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG);
    assert(BCRYPT_SUCCESS(ret));
    return inlen;
}

static size_t ptls_bcrypt_aead_do_encrypt_final(struct st_ptls_aead_context_t *_ctx, void *output)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    size_t oulenMax = ctx->super.algo->tag_size;
    ULONG cbResult = 0;
    NTSTATUS ret;

    /* Call the decryption */
    ret = BCryptDecrypt(ctx->bctx.hKey, (PUCHAR)NULL, (ULONG)0, (void *)&ctx->bctx.aead_params, ctx->bctx.iv,
                        (ULONG)ctx->super.algo->iv_size, output, (ULONG)oulenMax, &cbResult, BCRYPT_AUTH_MODE_IN_PROGRESS_FLAG);
    assert(BCRYPT_SUCCESS(ret));
    return ctx->super.algo->tag_size;
}

static size_t ptls_bcrypt_aead_do_decrypt(struct st_ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen,
                                          const void *iv, const void *aad, size_t aadlen)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    ULONG cbResult;
    size_t out_len_max = inlen - ctx->super.algo->tag_size;
    NTSTATUS ret;

    /* Save a copy of the IV*/
    memcpy(ctx->bctx.iv, iv, ctx->super.algo->iv_size);

    /* TODO: pPaddingInfo must point to BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure. */
    BCRYPT_INIT_AUTH_MODE_INFO(ctx->bctx.aead_params);
    /* TODO: find clarity on handling of nonce */
    ctx->bctx.nonce = 0;
    ctx->bctx.aead_params.pbNonce = (PUCHAR)&ctx->bctx.nonce;
    ctx->bctx.aead_params.cbNonce = (ULONG)sizeof(ctx->bctx.nonce);
    ctx->bctx.aead_params.pbAuthData = (PUCHAR)aad;
    ctx->bctx.aead_params.cbAuthData = (ULONG)aadlen;
    memset(ctx->bctx.tag, 0, sizeof(ctx->bctx.tag));
    /* TODO: check whether there is a need to set the precise tag size */
    ctx->bctx.aead_params.pbTag = (PUCHAR)ctx->bctx.tag;
    ctx->bctx.aead_params.cbTag = (ULONG)sizeof(ctx->bctx.tag);

    /* Call the decryption */
    ret = BCryptDecrypt(ctx->bctx.hKey, (PUCHAR)input, (ULONG)inlen, (void *)&ctx->bctx.aead_params, ctx->bctx.iv,
                        (ULONG)ctx->super.algo->iv_size, (PUCHAR)output, (ULONG)out_len_max, &cbResult, 0);

    if (BCRYPT_SUCCESS(ret)) {
        return (size_t)cbResult;
    } else {
        return SIZE_MAX;
    }
}

static int ptls_bcrypt_aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, wchar_t const *bcrypt_name,
                                         wchar_t const *bcrypt_mode, size_t bcrypt_mode_size)
{
    struct ptls_bcrypt_aead_context_t *ctx = (struct ptls_bcrypt_aead_context_t *)_ctx;
    HANDLE hAlgorithm = NULL;
    NTSTATUS ret;

    memset(&ctx->bctx, 0, sizeof(struct ptls_bcrypt_symmetric_param_t));

    ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

    if (BCRYPT_SUCCESS(ret)) {
        DWORD ko_size = 0;
        ULONG cbResult = 0;

        ret = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ko_size, (ULONG)sizeof(ko_size), &cbResult, 0);

        if (BCRYPT_SUCCESS(ret)) {
            ctx->bctx.key_object = (uint8_t *)malloc(ko_size);
            if (ctx->bctx.key_object == NULL) {
                ret = STATUS_NO_MEMORY;
            } else {
                ctx->bctx.cbKeyObject = ko_size;
            }
        }
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)bcrypt_mode, bcrypt_mode_size, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptGenerateSymmetricKey(hAlgorithm, &ctx->bctx.hKey, ctx->bctx.key_object, ctx->bctx.cbKeyObject, (PUCHAR)key,
                                         (ULONG)ctx->super.algo->key_size, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        ret = BCryptSetProperty(ctx->bctx.hKey, BCRYPT_CHAINING_MODE, (PUCHAR)bcrypt_mode,
                                (ULONG)(sizeof(wchar_t) * wcslen(bcrypt_mode)), 0);
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    if (BCRYPT_SUCCESS(ret)) {
        if (is_enc) {
            ctx->super.dispose_crypto = ptls_bcrypt_aead_dispose_crypto;
            ctx->super.do_decrypt = ptls_bcrypt_aead_do_decrypt;
            ctx->super.do_encrypt_init = NULL;
            ctx->super.do_encrypt_update = NULL;
            ctx->super.do_encrypt_final = NULL;
        } else {
            ctx->super.dispose_crypto = ptls_bcrypt_aead_dispose_crypto;
            ctx->super.do_decrypt = NULL;
            ctx->super.do_encrypt_init = ptls_bcrypt_aead_do_encrypt_init;
            ctx->super.do_encrypt_update = ptls_bcrypt_aead_do_encrypt_update;
            ctx->super.do_encrypt_final = ptls_bcrypt_aead_do_encrypt_final;
        }
        return 0;
    } else {
        ptls_bcrypt_aead_dispose_crypto(_ctx);
        return PTLS_ERROR_LIBRARY;
    }
}

static int ptls_bcrypt_aead_setup_crypto_aesgcm(ptls_aead_context_t *_ctx, int is_enc, const void *key)
{
    return ptls_bcrypt_aead_setup_crypto(_ctx, is_enc, key, BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_GCM,
                                         sizeof(BCRYPT_CHAIN_MODE_GCM));
}

/* Hash algorithms */
#if 0
/**
 * A hash context.
 */
typedef struct st_ptls_hash_context_t {
    /**
     * feeds additional data into the hash context
     */
    void (*update)(struct st_ptls_hash_context_t *ctx, const void *src, size_t len);
    /**
     * returns the digest and performs necessary operation specified by mode
     */
    void (*final)(struct st_ptls_hash_context_t *ctx, void *md, ptls_hash_final_mode_t mode);
    /**
     * creates a copy of the hash context
     */
    struct st_ptls_hash_context_t *(*clone_)(struct st_ptls_hash_context_t *src);
} ptls_hash_context_t;

/**
 * A hash algorithm and its properties.
 */
typedef const struct st_ptls_hash_algorithm_t {
    /**
     * block size
     */
    size_t block_size;
    /**
     * digest size
     */
    size_t digest_size;
    /**
     * constructor that creates the hash context
     */
    ptls_hash_context_t *(*create)(void);
    /**
     * digest of zero-length octets
     */
    uint8_t empty_digest[PTLS_MAX_DIGEST_SIZE];
} ptls_hash_algorithm_t;
#endif

typedef struct st_ptls_bcrypt_hash_param_t {
    wchar_t const *bcrypt_name;
    BCRYPT_HASH_HANDLE hHash;
    PUCHAR pbHashObject;
    ULONG cbHashObject;
    ULONG hash_size;
};

struct st_ptls_bcrypt_hash_context_t {
    ptls_hash_context_t super;
    struct st_ptls_bcrypt_hash_param_t ctx;
};

static void ptls_bcrypt_hash_update(struct st_ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;
    NTSTATUS ret = BCryptHashData(ctx->ctx.hHash, (PUCHAR)src, (ULONG)len, 0);
    assert(BCRYPT_SUCCESS(ret));
}

static struct st_ptls_bcrypt_hash_context_t *ptls_bcrypt_hash_context_free(struct st_ptls_bcrypt_hash_context_t *ctx)
{
    if (ctx->ctx.pbHashObject != NULL) {
        ptls_clear_memory(ctx->ctx.pbHashObject, ctx->ctx.cbHashObject);
        free(ctx->ctx.pbHashObject);
    }
    ptls_clear_memory(&ctx->ctx, sizeof(ctx->ctx));

    return NULL;
}

static ptls_hash_context_t *ptls_bcrypt_hash_clone(struct st_ptls_hash_context_t *_ctx);

static void ptls_bcrypt_hash_final(struct st_ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        /* TODO: Copying handle does not change the handle! */
        struct st_ptls_hash_context_t *clone_ctx = ptls_bcrypt_hash_clone(_ctx);

        if (clone_ctx != NULL) {
            ptls_bcrypt_hash_final(clone_ctx, md, PTLS_HASH_FINAL_MODE_FREE);
        } else {
            assert(clone_ctx != NULL);
        }
    } else {
        NTSTATUS ret;
        struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;

        if (md != NULL) {
            ret = BCryptFinishHash(ctx->ctx.hHash, md, ctx->ctx.hash_size, 0);
            assert(BCRYPT_SUCCESS(ret));
        }

        ret = BCryptDestroyHash(ctx->ctx.hHash);
        assert(BCRYPT_SUCCESS(ret));

        switch (mode) {
        case PTLS_HASH_FINAL_MODE_FREE:
            ctx = ptls_bcrypt_hash_context_free(ctx);
            break;
        case PTLS_HASH_FINAL_MODE_RESET: {
            BCRYPT_ALG_HANDLE hAlgorithm = NULL;
            ret = BCryptOpenAlgorithmProvider(&hAlgorithm, ctx->ctx.bcrypt_name, NULL, 0);
            if (BCRYPT_SUCCESS(ret)) {
                ctx->ctx.hHash = NULL;
                ret = BCryptCreateHash(hAlgorithm, &ctx->ctx.hHash, ctx->ctx.pbHashObject, ctx->ctx.cbHashObject, NULL, 0, 0);
                BCryptCloseAlgorithmProvider(hAlgorithm, 0);
            }
            assert(BCRYPT_SUCCESS(ret));
            break;
        }
        default:
            assert(!"FIXME");
            break;
        }
    }
}

static ptls_hash_context_t *ptls_bcrypt_hash_clone(struct st_ptls_hash_context_t *_ctx)
{
    struct st_ptls_bcrypt_hash_context_t *ctx = (struct st_ptls_bcrypt_hash_context_t *)_ctx;
    struct st_ptls_bcrypt_hash_context_t *clone_ctx;

    if ((clone_ctx = (struct st_ptls_bcrypt_hash_context_t *)malloc(sizeof(*ctx))) != NULL) {
        NTSTATUS ret;

        ptls_clear_memory(&clone_ctx->ctx, sizeof(clone_ctx->ctx));
        clone_ctx->super = (ptls_hash_context_t){ptls_bcrypt_hash_update, ptls_bcrypt_hash_final, ptls_bcrypt_hash_clone};
        clone_ctx->ctx.pbHashObject = (uint8_t *)malloc(ctx->ctx.cbHashObject);
        clone_ctx->ctx.cbHashObject = ctx->ctx.cbHashObject;
        clone_ctx->ctx.bcrypt_name = ctx->ctx.bcrypt_name;
        clone_ctx->ctx.hash_size = ctx->ctx.hash_size;

        if (clone_ctx->ctx.pbHashObject == NULL) {
            ret = STATUS_NO_MEMORY;
        } else {
            ctx->ctx.hHash = NULL;
            ptls_clear_memory(&clone_ctx->ctx.pbHashObject, clone_ctx->ctx.cbHashObject);
            ret = BCryptDuplicateHash(ctx->ctx.hHash, &clone_ctx->ctx.hHash, clone_ctx->ctx.pbHashObject,
                                      clone_ctx->ctx.cbHashObject, 0);
        }

        if (!BCRYPT_SUCCESS(ret)) {
            clone_ctx = ptls_bcrypt_hash_context_free(clone_ctx);
        }
    }

    return (ptls_hash_context_t *)clone_ctx;
}

static ptls_hash_context_t *ptls_bcrypt_hash_create(wchar_t const *bcrypt_name, ULONG hash_size)
{
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    NTSTATUS ret;
    struct st_ptls_bcrypt_hash_context_t *ctx;

    if ((ctx = (struct st_ptls_bcrypt_hash_context_t *)malloc(sizeof(*ctx))) != NULL) {
        ctx->super = (ptls_hash_context_t){ptls_bcrypt_hash_update, ptls_bcrypt_hash_final, ptls_bcrypt_hash_clone};
        memset(&ctx->ctx, 0, sizeof(struct st_ptls_bcrypt_hash_param_t));
        ctx->ctx.hash_size = hash_size;
        ctx->ctx.bcrypt_name = bcrypt_name;

        ret = BCryptOpenAlgorithmProvider(&hAlgorithm, bcrypt_name, NULL, 0);

        if (BCRYPT_SUCCESS(ret)) {
            DWORD hb_length = 0;
            ULONG cbResult = 0;

            ret =
                BCryptGetProperty(hAlgorithm, BCRYPT_HASH_BLOCK_LENGTH, (PUCHAR)&hb_length, (ULONG)sizeof(hb_length), &cbResult, 0);

            if (BCRYPT_SUCCESS(ret)) {
                ctx->ctx.pbHashObject = (uint8_t *)malloc(hb_length);
                if (ctx->ctx.pbHashObject == NULL) {
                    ret = STATUS_NO_MEMORY;
                } else {
                    ctx->ctx.cbHashObject = hb_length;
                }
            }
        }

        if (BCRYPT_SUCCESS(ret)) {
            ret = BCryptCreateHash(hAlgorithm, &ctx->ctx.hHash, ctx->ctx.pbHashObject, ctx->ctx.cbHashObject, NULL, 0, 0);
        }

        if (!BCRYPT_SUCCESS(ret)) {
            ctx = ptls_bcrypt_hash_context_free(ctx);
        }
    }

    if (hAlgorithm != NULL) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    }

    return (ptls_hash_context_t *)ctx;
}

static ptls_hash_context_t *ptls_bcrypt_sha256_create()
{
    return ptls_bcrypt_hash_create(BCRYPT_SHA256_ALGORITHM, PTLS_SHA256_DIGEST_SIZE);
}

static ptls_hash_context_t *ptls_bcrypt_sha384_create()
{
    return ptls_bcrypt_hash_create(BCRYPT_SHA384_ALGORITHM, PTLS_SHA384_DIGEST_SIZE);
}

/* Declaration of algorithms
 */

ptls_cipher_algorithm_t ptls_bcrypt_aes128ecb = {"AES128-ECB",
                                                 PTLS_AES128_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ecb};
ptls_cipher_algorithm_t ptls_bcrypt_aes256ecb = {"AES256-ECB",
                                                 PTLS_AES256_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ecb};

ptls_cipher_algorithm_t ptls_bcrypt_aes128ctr = {"AES128-CTR",
                                                 PTLS_AES128_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ctr};

ptls_cipher_algorithm_t ptls_bcrypt_aes256ctr = {"AES256-CTR",
                                                 PTLS_AES256_KEY_SIZE,
                                                 PTLS_AES_BLOCK_SIZE,
                                                 0 /* iv size */,
                                                 sizeof(struct ptls_bcrypt_symmetric_context_t),
                                                 ptls_bcrypt_cipher_setup_crypto_aes_ctr};

ptls_aead_algorithm_t ptls_bcrypt_aes128gcm = {"AES128-GCM",
                                               &ptls_bcrypt_aes128ecb,
                                               &ptls_bcrypt_aes128ctr,
                                               PTLS_AES128_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct ptls_bcrypt_aead_context_t),
                                               ptls_bcrypt_aead_setup_crypto_aesgcm};

ptls_aead_algorithm_t ptls_bcrypt_aes256gcm = {"AES256-GCM",
                                               &ptls_bcrypt_aes256ecb,
                                               &ptls_bcrypt_aes256ctr,
                                               PTLS_AES256_KEY_SIZE,
                                               PTLS_AESGCM_IV_SIZE,
                                               PTLS_AESGCM_TAG_SIZE,
                                               sizeof(struct ptls_bcrypt_aead_context_t),
                                               ptls_bcrypt_aead_setup_crypto_aesgcm};

ptls_hash_algorithm_t ptls_bcrypt_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, ptls_bcrypt_sha256_create,
                                            PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_bcrypt_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, ptls_bcrypt_sha384_create,
                                            PTLS_ZERO_DIGEST_SHA384};

ptls_cipher_suite_t ptls_bcrypt_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_bcrypt_aes128gcm,
                                                   &ptls_bcrypt_sha256};
ptls_cipher_suite_t ptls_bcrypt_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_bcrypt_aes256gcm,
                                                   &ptls_bcrypt_sha384};

#ifdef PTLS_BCRYPT_TODO
int ptls_bcrypt_init_verify_certificate(ptls_bcrypt_verify_certificate_t *self, X509_STORE *store)
{
    /* TODO: Replace with bcrypt library */
    *self = (ptls_bcrypt_verify_certificate_t){{verify_cert}};

    if (store != NULL) {
        X509_STORE_up_ref(store);
        self->cert_store = store;
    } else {
        /* use default store */
        if ((self->cert_store = ptls_bcrypt_create_default_certificate_store()) == NULL)
            return -1;
    }

    return 0;
}

void ptls_bcrypt_dispose_verify_certificate(ptls_bcrypt_verify_certificate_t *self)
{
    X509_STORE_free(self->cert_store);
    free(self);
}

X509_STORE *ptls_bcrypt_create_default_certificate_store(void)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    if ((store = X509_STORE_new()) == NULL)
        goto Error;
    if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL)
        goto Error;
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) == NULL)
        goto Error;
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    return store;
Error:
    if (store != NULL)
        X509_STORE_free(store);
    return NULL;
}

#define TICKET_LABEL_SIZE 16
#define TICKET_IV_SIZE EVP_MAX_IV_LENGTH

int ptls_bcrypt_encrypt_ticket(ptls_buffer_t *buf, ptls_iovec_t src,
                               int (*cb)(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc))
{
    /* TODO: rewrite with bcrypt functions */
    EVP_CIPHER_CTX *cctx = NULL;
    HMAC_CTX *hctx = NULL;
    uint8_t *dst;
    int clen, ret;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((hctx = HMAC_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    if ((ret = ptls_buffer_reserve(buf, TICKET_LABEL_SIZE + TICKET_IV_SIZE + src.len + EVP_MAX_BLOCK_LENGTH + EVP_MAX_MD_SIZE)) !=
        0)
        goto Exit;
    dst = buf->base + buf->off;

    /* fill label and iv, as well as obtaining the keys */
    if (!(*cb)(dst, dst + TICKET_LABEL_SIZE, cctx, hctx, 1)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += TICKET_LABEL_SIZE + TICKET_IV_SIZE;

    /* encrypt */
    if (!EVP_EncryptUpdate(cctx, dst, &clen, src.base, (int)src.len)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += clen;
    if (!EVP_EncryptFinal_ex(cctx, dst, &clen)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += clen;

    /* append hmac */
    if (!HMAC_Update(hctx, buf->base + buf->off, dst - (buf->base + buf->off)) || !HMAC_Final(hctx, dst, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    dst += HMAC_size(hctx);

    assert(dst <= buf->base + buf->capacity);
    buf->off += dst - (buf->base + buf->off);
    ret = 0;

Exit:
    if (cctx != NULL)
        cleanup_cipher_ctx(cctx);
    if (hctx != NULL)
        HMAC_CTX_free(hctx);
    return ret;
}

int ptls_bcrypt_decrypt_ticket(ptls_buffer_t *buf, ptls_iovec_t src,
                               int (*cb)(unsigned char *key_name, unsigned char *iv, EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc))
{
    /* TODO: replace with bcrypt functions */
    EVP_CIPHER_CTX *cctx = NULL;
    HMAC_CTX *hctx = NULL;
    int clen, ret;

    if ((cctx = EVP_CIPHER_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if ((hctx = HMAC_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* obtain cipher and hash context.
     * Note: no need to handle renew, since in picotls we always send a new ticket to minimize the chance of ticket reuse */
    if (src.len < TICKET_LABEL_SIZE + TICKET_IV_SIZE) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    if (!(*cb)(src.base, src.base + TICKET_LABEL_SIZE, cctx, hctx, 0)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }

    /* check hmac, and exclude label, iv, hmac */
    size_t hmac_size = HMAC_size(hctx);
    if (src.len < TICKET_LABEL_SIZE + TICKET_IV_SIZE + hmac_size) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }
    src.len -= hmac_size;
    uint8_t hmac[EVP_MAX_MD_SIZE];
    if (!HMAC_Update(hctx, src.base, src.len) || !HMAC_Final(hctx, hmac, NULL)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (!ptls_mem_equal(src.base + src.len, hmac, hmac_size)) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }
    src.base += TICKET_LABEL_SIZE + TICKET_IV_SIZE;
    src.len -= TICKET_LABEL_SIZE + TICKET_IV_SIZE;

    /* decrypt */
    if ((ret = ptls_buffer_reserve(buf, src.len)) != 0)
        goto Exit;
    if (!EVP_DecryptUpdate(cctx, buf->base + buf->off, &clen, src.base, (int)src.len)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    buf->off += clen;
    if (!EVP_DecryptFinal_ex(cctx, buf->base + buf->off, &clen)) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    buf->off += clen;

    ret = 0;

Exit:
    if (cctx != NULL)
        cleanup_cipher_ctx(cctx);
    if (hctx != NULL)
        HMAC_CTX_free(hctx);
    return ret;
}
#endif

#ifdef PRLS_BCRYPT_TODO
/* TODO: replace with bcrypt functions */
ptls_key_exchange_algorithm_t ptls_bcrypt_secp256r1 = {PTLS_GROUP_SECP256R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_X9_62_prime256v1};
#if ptls_bcrypt_HAVE_SECP384R1
ptls_key_exchange_algorithm_t ptls_bcrypt_secp384r1 = {PTLS_GROUP_SECP384R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_secp384r1};
#endif
#if ptls_bcrypt_HAVE_SECP521R1
ptls_key_exchange_algorithm_t ptls_bcrypt_secp521r1 = {PTLS_GROUP_SECP521R1, x9_62_create_key_exchange, secp_key_exchange,
                                                       NID_secp521r1};
#endif
#if ptls_bcrypt_HAVE_X25519
ptls_key_exchange_algorithm_t ptls_bcrypt_x25519 = {PTLS_GROUP_X25519, evp_keyex_create, evp_keyex_exchange, NID_X25519};
#endif

ptls_key_exchange_algorithm_t *ptls_bcrypt_key_exchanges[] = {&ptls_bcrypt_secp256r1, NULL};
#endif

#endif /* _WINDOWS */