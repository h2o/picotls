#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"

#include "mbedtls/chacha20.h"
#include "mbedtls/ecdh.h"

/* Init and free functions. Init should be used before starting using
* library functions. Free should be used before leaving the program.
*/

void ptls_mbedtls_free()
{
    mbedtls_psa_crypto_free();
}

int ptls_mbedtls_init()
{
    int ret = 0;
    psa_status_t status;
    if ((status = psa_crypto_init()) != PSA_SUCCESS) {
        ret = -1;
    }

    return ret;
}

/* Random number generator.
* This is a call to the PSA random number generator, which according
* to the documentation meets cryptographic requirements.
*/
void ptls_mbedtls_random_bytes(void* buf, size_t len)
{
    psa_generate_random((uint8_t*)buf, len);
}

/* Definitions for hash algorithms.
* In Picotls, these are described by the stucture
* ptls_hash_algorithm_t, which include the function
* pointer for creation of the hash context.
* 
* The structure contains a function pointer to the
* "create" function that creates a hash operation,
* which itself contains three function pointers:
* 
* void (*update)(struct st_ptls_hash_context_t *ctx, const void *src, size_t len);
* void (*final)(struct st_ptls_hash_context_t *ctx, void *md, ptls_hash_final_mode_t mode);
* struct st_ptls_hash_context_t *(*clone_)(struct st_ptls_hash_context_t *src);
* 
*/

typedef struct st_ptls_mbedtls_hash_ctx_t {
    ptls_hash_context_t super;
    psa_algorithm_t alg;
    size_t hash_size;
    psa_hash_operation_t operation;
} ptls_mbedtls_hash_ctx_t;

static void ptls_mbedtls_hash_update(struct st_ptls_hash_context_t* _ctx, const void* src, size_t len)
{
    ptls_mbedtls_hash_ctx_t* ctx = (ptls_mbedtls_hash_ctx_t*)_ctx;

    (void) psa_hash_update(&ctx->operation, (const uint8_t *) src, len);
}

static void ptls_mbedtls_hash_final(struct st_ptls_hash_context_t* _ctx, void* md, ptls_hash_final_mode_t mode);

static struct st_ptls_hash_context_t* ptls_mbedtls_hash_clone(struct st_ptls_hash_context_t* _src)
{
    ptls_mbedtls_hash_ctx_t* ctx = (ptls_mbedtls_hash_ctx_t*)malloc(sizeof(ptls_mbedtls_hash_ctx_t));
    const ptls_mbedtls_hash_ctx_t* src = (const ptls_mbedtls_hash_ctx_t*)_src;

    if (ctx != NULL) {
        ptls_mbedtls_hash_ctx_t* src = (ptls_mbedtls_hash_ctx_t*)_src;
        memset(&ctx->operation, 0, sizeof(mbedtls_sha256_context));
        ctx->super.clone_ = ptls_mbedtls_hash_clone;
        ctx->super.update = ptls_mbedtls_hash_update;
        ctx->super.final = ptls_mbedtls_hash_final;
        ctx->alg = src->alg;
        ctx->hash_size = src->hash_size;
        if (psa_hash_clone(&src->operation, &ctx->operation) != 0) {
            free(ctx);
            ctx = NULL;
        }
    }
    return (ptls_hash_context_t*)ctx;
}

static void ptls_mbedtls_hash_final(struct st_ptls_hash_context_t* _ctx, void* md, ptls_hash_final_mode_t mode)
{
    ptls_mbedtls_hash_ctx_t* ctx = (ptls_mbedtls_hash_ctx_t*)_ctx;

    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        struct st_ptls_hash_context_t* cloned = ptls_mbedtls_hash_clone(_ctx);

        if (cloned != NULL) {
            ptls_mbedtls_hash_final(cloned, md, PTLS_HASH_FINAL_MODE_FREE);
        }
    } else {
        if (md != NULL) {
            size_t hash_length = 0;
            if (psa_hash_finish(&ctx->operation, md, ctx->hash_size, &hash_length) != 0) {
                memset(md, 0, ctx->hash_size);
            }
        }

        if (mode == PTLS_HASH_FINAL_MODE_FREE) {
            (void)psa_hash_abort(&ctx->operation);
            free(ctx);
        }
        else {
            /* if mode = reset, reset the context */
            memset(&ctx->operation, 0, sizeof(ctx->operation));
            (void)psa_hash_setup(&ctx->operation, ctx->alg);
        }
    }
}

ptls_hash_context_t* ptls_mbedtls_hash_create(psa_algorithm_t alg, size_t hash_size)
{
    ptls_mbedtls_hash_ctx_t* ctx = (ptls_mbedtls_hash_ctx_t*)malloc(sizeof(ptls_mbedtls_hash_ctx_t));

    if (ctx != NULL) {
        memset(&ctx->operation, 0, sizeof(ctx->operation));
        ctx->alg = alg;
        ctx->hash_size = hash_size;
        ctx->super.clone_ = ptls_mbedtls_hash_clone;
        ctx->super.update = ptls_mbedtls_hash_update;
        ctx->super.final = ptls_mbedtls_hash_final;
        if (psa_hash_setup(&ctx->operation, alg) != 0){
            free(ctx);
            ctx = NULL;
        }
    }
    return (ptls_hash_context_t*)ctx;
}

ptls_hash_context_t* ptls_mbedtls_sha256_create(void)
{
    return ptls_mbedtls_hash_create(PSA_ALG_SHA_256, PTLS_SHA256_DIGEST_SIZE);
}

ptls_hash_context_t* ptls_mbedtls_sha512_create(void)
{
    return ptls_mbedtls_hash_create(PSA_ALG_SHA_512, PTLS_SHA512_DIGEST_SIZE);
}


ptls_hash_algorithm_t ptls_mbedtls_sha256 = {"sha256", PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, ptls_mbedtls_sha256_create,
PTLS_ZERO_DIGEST_SHA256};

ptls_hash_algorithm_t ptls_mbedtls_sha512 = {"SHA512", PTLS_SHA512_BLOCK_SIZE, PTLS_SHA512_DIGEST_SIZE, ptls_mbedtls_sha512_create,
PTLS_ZERO_DIGEST_SHA512};

#if defined(MBEDTLS_SHA384_C)
ptls_hash_context_t* ptls_mbedtls_sha384_create(void)
{
    return ptls_mbedtls_hash_create(PSA_ALG_SHA_384, PTLS_SHA384_DIGEST_SIZE);
}

ptls_hash_algorithm_t ptls_mbedtls_sha384 = {"SHA384", PTLS_SHA384_BLOCK_SIZE, 
PTLS_SHA384_DIGEST_SIZE, ptls_mbedtls_sha384_create,
PTLS_ZERO_DIGEST_SHA384};
#endif /* MBEDTLS_SHA384_C */

/*
* Generic implementation of a cipher using the PSA API
*/
struct st_ptls_mbedtls_cipher_context_t {
    ptls_cipher_context_t super;
    psa_algorithm_t alg;
    size_t iv_length;
    int is_enc;
    int is_op_in_progress;
    mbedtls_svc_key_id_t key;
    psa_cipher_operation_t operation;
};


static void ptls_mbedtls_cipher_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;

    if (ctx->is_op_in_progress) {
        psa_cipher_abort(&ctx->operation);
        ctx->is_op_in_progress = 0;
    }

    memset(&ctx->operation, 0, sizeof(ctx->operation));
    if (ctx->is_enc) {
        (void)psa_cipher_encrypt_setup(&ctx->operation, ctx->key, ctx->alg);
    }
    else {
        (void)psa_cipher_decrypt_setup(&ctx->operation, ctx->key, ctx->alg);
    }
    if (ctx->iv_length > 0) {
        (void)psa_cipher_set_iv(&ctx->operation, (const uint8_t*)iv, ctx->iv_length);
    }
    ctx->is_op_in_progress = 1;
}

static void ptls_mbedtls_cipher_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;
    size_t outlen = 0;

    (void) psa_cipher_update(&ctx->operation, (const uint8_t*)input, len, (uint8_t*)output, len, &outlen);
}

static void ptls_mbedtls_cipher_dispose(ptls_cipher_context_t *_ctx)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;
    if (ctx->is_op_in_progress) {
        psa_cipher_abort(&ctx->operation);
        ctx->is_op_in_progress = 0;
    }
    psa_destroy_key(ctx->key);
}

static int ptls_mbedtls_cipher_setup_key(mbedtls_svc_key_id_t* key_id, int is_enc, psa_algorithm_t alg, psa_key_type_t key_type,
    size_t key_bits, uint8_t * key_bytes)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    int ret = 0;

    psa_set_key_usage_flags(&attributes,
        (is_enc)?PSA_KEY_USAGE_ENCRYPT:PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_bits(&attributes, key_bits);
    /* Import key */
    if (psa_import_key(&attributes, key_bytes, key_bits / 8,
        key_id) != PSA_SUCCESS) {
        ret = PTLS_ERROR_LIBRARY;
    }

    return ret;
}

static int ptls_mbedtls_cipher_setup_crypto(ptls_cipher_context_t* _ctx, int is_enc, const void* key_bytes,
    psa_algorithm_t alg, size_t iv_length, psa_key_type_t key_type, size_t key_bits)
{
    struct st_ptls_mbedtls_cipher_context_t *ctx = (struct st_ptls_mbedtls_cipher_context_t *)_ctx;
    int ret = 0;

    ctx->alg = alg;
    ctx->is_enc = is_enc;
    ctx->iv_length = iv_length;

    /* Initialize the key attributes */
    ret = ptls_mbedtls_cipher_setup_key(&ctx->key, is_enc, alg, key_type, key_bits, key_bytes);
    /* Finish initializing the context */
    ctx->super.do_dispose = ptls_mbedtls_cipher_dispose;
    ctx->super.do_init = ptls_mbedtls_cipher_init;
    ctx->super.do_transform = NULL;


    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_cipher_transform;
    }

    return ret;
}

/*
* Implementation of AES128_ECB using the PSA API:
*/
static int ptls_mbedtls_cipher_setup_aes128_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes)
{
    return ptls_mbedtls_cipher_setup_crypto(_ctx, is_enc, key_bytes,
        PSA_ALG_ECB_NO_PADDING, 0, PSA_KEY_TYPE_AES, 128);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes128ecb = {
    "AES128-ECB",
    PTLS_AES128_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    0 /* iv size */,
    sizeof(struct st_ptls_mbedtls_cipher_context_t),
    ptls_mbedtls_cipher_setup_aes128_ecb};

/*
* Implementation of AES256_ECB using the PSA API:
*/
static int ptls_mbedtls_cipher_setup_aes256_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes)
{
    return ptls_mbedtls_cipher_setup_crypto(_ctx, is_enc, key_bytes,
        PSA_ALG_ECB_NO_PADDING, 0, PSA_KEY_TYPE_AES, 256);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes256ecb = {
    "AES256-ECB",
    PTLS_AES128_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    0 /* iv size */,
    sizeof(struct st_ptls_mbedtls_cipher_context_t),
    ptls_mbedtls_cipher_setup_aes256_ecb};

/*
* Implementation of AES128_CTR using the PSA API:
*/

static int ptls_mbedtls_cipher_setup_aes128_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes)
{
    return ptls_mbedtls_cipher_setup_crypto(_ctx, is_enc, key_bytes,
        PSA_ALG_CTR, 16, PSA_KEY_TYPE_AES, 128);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr = {
    "AES128-CTR",
    PTLS_AES128_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    16 /* iv size */,
    sizeof(struct st_ptls_mbedtls_cipher_context_t),
    ptls_mbedtls_cipher_setup_aes128_ctr};

/*
* Implementation of AES128_CTR using the PSA API:
*/

static int ptls_mbedtls_cipher_setup_aes256_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes)
{
    return ptls_mbedtls_cipher_setup_crypto(_ctx, is_enc, key_bytes,
        PSA_ALG_CTR, 16, PSA_KEY_TYPE_AES, 256);
}

ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr = {
    "AES128-CTR",
    PTLS_AES256_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    16 /* iv size */,
    sizeof(struct st_ptls_mbedtls_cipher_context_t),
    ptls_mbedtls_cipher_setup_aes256_ctr};


#if 0
/*
* Implementation of CHACHA20 using the PSA API.
* This is disabled for now, as there seems to be an issue when
* setting the 16 bytes long IV that we need.
*/
static int ptls_mbedtls_cipher_setup_crypto_chacha20(ptls_cipher_context_t *_ctx, int is_enc, const void *key_bytes)
{
    return ptls_mbedtls_cipher_setup_crypto(_ctx, is_enc, key_bytes,
        PSA_ALG_STREAM_CIPHER, 16, PSA_KEY_TYPE_CHACHA20, 256);
}

ptls_cipher_algorithm_t ptls_mbedtls_chacha20 = {
    "CHACHA20", PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct st_ptls_mbedtls_cipher_context_t),
    ptls_mbedtls_cipher_setup_crypto_chacha20};
#else
/* Implementation of ChaCha20 using the low level ChaCha20 API.
* TODO: remove this and the reference to chacha20.h as soon as
* the IV bug in the generic implementation is fixed.
*/
struct st_ptls_mbedtls_chacha20_context_t {
    ptls_cipher_context_t super;
    mbedtls_chacha20_context mctx;
};

static void ptls_mbedtls_chacha20_init(ptls_cipher_context_t *_ctx, const void *v_iv)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;
    const uint8_t* iv = (const uint8_t*)v_iv;
    uint32_t ctr = iv[0] | ((uint32_t)iv[1] << 8) | ((uint32_t)iv[2] << 16) | ((uint32_t)iv[3] << 24);

    (void)mbedtls_chacha20_starts(&ctx->mctx, (const uint8_t*)(iv+4), ctr);
}

static void ptls_mbedtls_chacha20_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;

    if (mbedtls_chacha20_update(&ctx->mctx, len, 
        (const uint8_t*)input, (uint8_t*)output) != 0) {
        memset(output, 0, len);
    }
}

static void ptls_mbedtls_chacha20_dispose(ptls_cipher_context_t *_ctx)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;
    mbedtls_chacha20_free(&ctx->mctx);
}

static int ptls_mbedtls_cipher_setup_crypto_chacha20(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct st_ptls_mbedtls_chacha20_context_t *ctx = (struct st_ptls_mbedtls_chacha20_context_t *)_ctx;
    int ret = 0;

    mbedtls_chacha20_init(&ctx->mctx);
    ret = mbedtls_chacha20_setkey(&ctx->mctx, (const uint8_t*)key);

    ctx->super.do_dispose = ptls_mbedtls_chacha20_dispose;
    ctx->super.do_init = ptls_mbedtls_chacha20_init;
    ctx->super.do_transform = NULL;

    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_chacha20_transform;
    }

    return ret;
}

ptls_cipher_algorithm_t ptls_mbedtls_chacha20 = {
    "CHACHA20", PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct st_ptls_mbedtls_chacha20_context_t),
    ptls_mbedtls_cipher_setup_crypto_chacha20};
#endif

/* Definitions of AEAD algorithms.
* 
* For the picotls API, AEAD algorithms are created by calling:
* 
* ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead,
*       ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
*                                   const char *label_prefix)
* That procedure will allocate memory and create keys, and then call
* a provider specific function:
* 
*   if (aead->setup_crypto(ctx, is_enc, key, iv) != 0) {
*       free(ctx);
*       return NULL;
*   }
* 
* The function will finish completing the aead structure, perform
* initialization, and then document the function pointers:
* 
* ctx->super.dispose_crypto: release all resourc
* ctx->super.do_get_iv: return IV
* ctx->super.do_set_iv: set IV value
* ctx->super.do_decrypt: decrypt function
* ctx->super.do_encrypt_init: start encrypting one message
* ctx->super.do_encrypt_update: feed more ciphertext to descriptor
* ctx->super.do_encrypt_final: finalize encryption, including AEAD checksum
* ctx->super.do_encrypt: single shot variant of init/update/final
* ctx->super.do_encrypt_v: scatter gather version of do encrypt
* 
* The aead context also documents the underlying "ECB" and "CTR" modes.
* In QUIC, these are used for PN encryption.
* 
* TODO: declare other algorithms besides AES128_GCM
*/

struct ptls_mbedtls_aead_param_t {
    uint8_t static_iv[PTLS_MAX_IV_SIZE];
    psa_algorithm_t alg;
    psa_key_id_t key;
    psa_aead_operation_t op;
    size_t extra_bytes;
    int is_op_in_progress;
};

struct ptls_mbedtls_aead_context_t {
    struct st_ptls_aead_context_t super;
    struct ptls_mbedtls_aead_param_t mctx;
};

void ptls_mbedtls_aead_dispose_crypto(struct st_ptls_aead_context_t* _ctx)
{
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;
    if (ctx->mctx.is_op_in_progress) {
        psa_aead_abort(&ctx->mctx.op);
        ctx->mctx.is_op_in_progress = 0;
    }
    psa_destroy_key(ctx->mctx.key);
}


static void ptls_mbedtls_aead_get_iv(ptls_aead_context_t *_ctx, void *iv)
{
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;

    memcpy(iv, ctx->mctx.static_iv, ctx->super.algo->iv_size);
}

static void ptls_mbedtls_aead_set_iv(ptls_aead_context_t *_ctx, const void *iv)
{
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;

    memcpy(ctx->mctx.static_iv, iv, ctx->super.algo->iv_size);
}

void ptls_mbedtls_aead_do_encrypt_init(struct st_ptls_aead_context_t* _ctx, uint64_t seq, const void* aad, size_t aadlen)
{
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;
    psa_status_t status;

    if (ctx->mctx.is_op_in_progress) {
        psa_aead_abort(&ctx->mctx.op);   /* required on errors, harmless on success */
        ctx->mctx.is_op_in_progress = 0;
    }

    ctx->mctx.is_op_in_progress = 1;
    memset(&ctx->mctx.op, 0, sizeof(ctx->mctx.op));

    status = psa_aead_encrypt_setup(&ctx->mctx.op, ctx->mctx.key, ctx->mctx.alg);

    if (status == PSA_SUCCESS) {
        /* set the nonce. */
        uint8_t iv[PTLS_MAX_IV_SIZE];
        ptls_aead__build_iv(ctx->super.algo, iv, ctx->mctx.static_iv, seq);
        status = psa_aead_set_nonce(&ctx->mctx.op, iv, ctx->super.algo->iv_size);
    }

    if (status == PSA_SUCCESS) {
        status = psa_aead_update_ad(&ctx->mctx.op, aad, aadlen);
    }

    if (status != PSA_SUCCESS) {
        psa_aead_abort(&ctx->mctx.op);   /* required on errors, harmless on success */
        ctx->mctx.is_op_in_progress = 0;
    }
}

size_t ptls_mbedtls_aead_do_encrypt_update(struct st_ptls_aead_context_t* _ctx, void* output, const void* input, size_t inlen)
{
    size_t olen = 0;
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;

    if (ctx->mctx.is_op_in_progress) {
        size_t available = inlen + ctx->mctx.extra_bytes;
        psa_status_t status = psa_aead_update(&ctx->mctx.op, input, inlen, (uint8_t *)output, available + ctx->super.algo->tag_size, &olen);

        if (status == PSA_SUCCESS) {
            if (olen < available) {
                ctx->mctx.extra_bytes = available - olen;
            }
            else {
                ctx->mctx.extra_bytes = 0;
            }
        }
        else {
            psa_aead_abort(&ctx->mctx.op);   /* required on errors */
            ctx->mctx.is_op_in_progress = 0;
        }
    }

    return olen;
}

size_t ptls_mbedtls_aead_do_encrypt_final(struct st_ptls_aead_context_t* _ctx, void* output)
{
    size_t olen = 0;
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;

    if (ctx->mctx.is_op_in_progress) {
        unsigned char tag[PSA_AEAD_TAG_MAX_SIZE];
        size_t olen_tag = 0;
        size_t available = ctx->mctx.extra_bytes;
        uint8_t* p = (uint8_t*)output;
        psa_status_t status = psa_aead_finish(&ctx->mctx.op, p, available + ctx->super.algo->tag_size, &olen,
            tag, sizeof(tag), &olen_tag);

        if (status == PSA_SUCCESS) {
            p += olen;
            memcpy(p, tag, ctx->super.algo->tag_size);
            olen += ctx->super.algo->tag_size;
        }
        else {
            psa_aead_abort(&ctx->mctx.op);   /* required on errors */
        }
        ctx->mctx.is_op_in_progress = 0;
    }

    return(olen);
}

void ptls_mbedtls_aead_do_encrypt_v(struct st_ptls_aead_context_t* _ctx, void* output, ptls_iovec_t* input, size_t incnt, uint64_t seq,
    const void* aad, size_t aadlen)
{
    unsigned char* p = (uint8_t*)output;

    ptls_mbedtls_aead_do_encrypt_init(_ctx, seq, aad, aadlen);

    for (size_t i = 0; i < incnt; i++) {
        p += ptls_mbedtls_aead_do_encrypt_update(_ctx, p, input[i].base, input[i].len);
    }

    (void)ptls_mbedtls_aead_do_encrypt_final(_ctx, p);
}

void ptls_mbedtls_aead_do_encrypt(struct st_ptls_aead_context_t* _ctx, void* output, const void* input, size_t inlen, uint64_t seq,
    const void* aad, size_t aadlen, ptls_aead_supplementary_encryption_t* supp)
{
    ptls_iovec_t in_v;
    in_v.base = (uint8_t*)input;
    in_v.len = inlen;

    ptls_mbedtls_aead_do_encrypt_v(_ctx, output, &in_v, 1, seq, aad, aadlen);
}

size_t ptls_mbedtls_aead_do_decrypt(struct st_ptls_aead_context_t* _ctx, void* output, const void* input, size_t inlen, uint64_t seq,
    const void* aad, size_t aadlen)
{
    size_t o_len = 0;
    uint8_t iv[PTLS_MAX_IV_SIZE];
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;
    psa_status_t status;
    /* set the nonce. */
    ptls_aead__build_iv(ctx->super.algo, iv, ctx->mctx.static_iv, seq);

    status = psa_aead_decrypt(ctx->mctx.key, ctx->mctx.alg, iv, ctx->super.algo->iv_size, (uint8_t*)aad, aadlen,
        (uint8_t*)input, inlen, (uint8_t*)output, inlen, &o_len);
    if (status != PSA_SUCCESS) {
        o_len = inlen + 1;
    }
    return o_len;
}

static int ptls_mbedtls_aead_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key_bytes, const void *iv)
{
    int ret = 0;
    struct ptls_mbedtls_aead_context_t* ctx =
        (struct ptls_mbedtls_aead_context_t*)_ctx;
    size_t key_bits;
    psa_key_type_t key_type;

    /* set mbed specific context to NULL, just to be sure */
    memset(&ctx->mctx, 0, sizeof(struct ptls_mbedtls_aead_param_t));

    /* deduce the PSA algorithm from the name */
    if (strcmp(ctx->super.algo->name, "AES128-GCM") == 0) {
        ctx->mctx.alg = PSA_ALG_GCM;
        key_bits = 128;
        key_type = PSA_KEY_TYPE_AES;
    } else if (strcmp(ctx->super.algo->name, "AES256-GCM") == 0) {
        ctx->mctx.alg = PSA_ALG_GCM;
        key_bits = 256;
        key_type = PSA_KEY_TYPE_AES;
    } else if (strcmp(ctx->super.algo->name, "AES128-GCM_8") == 0) {
        ctx->mctx.alg = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, 8);
        key_bits = 128;
        key_type = PSA_KEY_TYPE_AES;
    } else if (strcmp(ctx->super.algo->name, "CHACHA20-POLY1305") == 0) {
        ctx->mctx.alg = PSA_ALG_CHACHA20_POLY1305;
        key_bits = 256;
        key_type = PSA_KEY_TYPE_CHACHA20;
    } else {
        ret = PTLS_ERROR_LIBRARY;
    }

    /* Initialize the key attributes */
    if (ret == 0) {
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_usage_flags(&attributes, 
            (is_enc)?PSA_KEY_USAGE_ENCRYPT:PSA_KEY_USAGE_DECRYPT);
        psa_set_key_algorithm(&attributes, ctx->mctx.alg);
        psa_set_key_type(&attributes, key_type);
        psa_set_key_bits(&attributes, key_bits);
        /* Import key */
        if (psa_import_key(&attributes, key_bytes, key_bits / 8,
            &ctx->mctx.key) != PSA_SUCCESS) {
            ret = PTLS_ERROR_LIBRARY;
        }
    }

    if (ret == 0) {
        /* Store the static IV */
        if (ctx->super.algo->iv_size > PTLS_MAX_IV_SIZE) {
            ret = PTLS_ERROR_LIBRARY;
        }
        else {
            memcpy(ctx->mctx.static_iv, iv, ctx->super.algo->iv_size);
            ctx->mctx.is_op_in_progress = 0;
        }
    }

    /* set the pointers to the individual functions */
    if (ret == 0) {
        if (is_enc) {
            ctx->super.do_encrypt_init = ptls_mbedtls_aead_do_encrypt_init;
            ctx->super.do_encrypt_update = ptls_mbedtls_aead_do_encrypt_update;
            ctx->super.do_encrypt_final = ptls_mbedtls_aead_do_encrypt_final;
            ctx->super.do_encrypt = ptls_mbedtls_aead_do_encrypt;
            ctx->super.do_encrypt_v = ptls_mbedtls_aead_do_encrypt_v;
        }
        else {
            ctx->super.do_decrypt = ptls_mbedtls_aead_do_decrypt;
        }
        ctx->super.dispose_crypto = ptls_mbedtls_aead_dispose_crypto;
        ctx->super.do_get_iv = ptls_mbedtls_aead_get_iv;
        ctx->super.do_set_iv = ptls_mbedtls_aead_set_iv;
    }

    return ret;
}

ptls_aead_algorithm_t ptls_mbedtls_aes128gcm = {
    "AES128-GCM",
    PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
    PTLS_AESGCM_INTEGRITY_LIMIT,
    &ptls_mbedtls_aes128ctr,
    &ptls_mbedtls_aes128ecb,
    PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE,
    PTLS_AESGCM_TAG_SIZE,
    {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
    0,
    0,
    sizeof(struct ptls_mbedtls_aead_context_t),
    ptls_mbedtls_aead_setup_crypto
};

ptls_aead_algorithm_t ptls_mbedtls_aes256gcm = {
    "AES256-GCM",
    PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
    PTLS_AESGCM_INTEGRITY_LIMIT,
    &ptls_mbedtls_aes256ctr,
    &ptls_mbedtls_aes256ecb,
    PTLS_AES256_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE,
    PTLS_AESGCM_TAG_SIZE,
    {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
    0,
    0,
    sizeof(struct ptls_mbedtls_aead_context_t),
    ptls_mbedtls_aead_setup_crypto
};

ptls_aead_algorithm_t ptls_mbedtls_chacha20poly1305 = {
    "CHACHA20-POLY1305",
    PTLS_CHACHA20POLY1305_CONFIDENTIALITY_LIMIT,
    PTLS_CHACHA20POLY1305_INTEGRITY_LIMIT,
    &ptls_mbedtls_chacha20,
    NULL,
    PTLS_CHACHA20_KEY_SIZE,
    PTLS_CHACHA20POLY1305_IV_SIZE,
    PTLS_CHACHA20POLY1305_TAG_SIZE,
    {PTLS_TLS12_CHACHAPOLY_FIXED_IV_SIZE, PTLS_TLS12_CHACHAPOLY_RECORD_IV_SIZE},
    0,
    0,
    sizeof(struct ptls_mbedtls_aead_context_t),
    ptls_mbedtls_aead_setup_crypto
};

/* Key exchange algorithms.
* The Picotls framework defines these algorithms as ptls_key_exchange_algorithm_t,
* a structure containing two function pointers:
* 
* int (*create)(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **ctx);
* int (*exchange)(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
*     ptls_iovec_t peerkey);
* The "create" call is used on the client. It documents the ptls_key_exchange_context_t, which contains
* the public key prepared by the client, as an iovec, and a function pointer:
* 
* int (*on_exchange)(struct st_ptls_key_exchange_context_t **keyex, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey);
* 
* The public key of the client is passed to the server an ends up as "peerkey" argument to the (exchange) function.
* That function documents the server's public key, and the secret coputed by combining server and client key.
* 
* When the client receives the server hello, the stack calls the "on_exchange" callback, passing the context
* previously created by the client and the public key of the peer, so the client can compute its own
* version of the secret.
* 
* The following code uses the MbedTLS API to create the "create", "exchange" and "on_exchange" functions.
*/

/* TODO: use the PSA API, 
* psa_generate_key
* 
*/
#define PTLS_MBEDTLS_ECDH_PUBKEY_MAX 129
#define TYPE_MBEDTLS_ECDH_UNCOMPRESSED_PUBLIC_KEY 4	

struct ptls_mbedtls_ecdh_key_exchange_context_t {
    ptls_key_exchange_context_t super;
    mbedtls_ecdh_context ecdh_ctx;
    uint8_t pub[PTLS_MBEDTLS_ECDH_PUBKEY_MAX];
};

#if 0
static int ptls_mbedtls_ecdh_gen_public(struct ptls_mbedtls_ecdh_key_exchange_context_t * ctx)
{
    int ret = 0;
    ret = mbedtls_ecdh_setup(&ctx->ecdh_ctx, ctx->group_id /* MBEDTLS_ECP_DP_CURVE25519 */);
    if (ret == 0) {
        ret = mbedtls_ecdh_make_params(&ctx->ecdh_ctx, &cli_olen, cli_to_srv,
            sizeof(cli_to_srv),
            mbedtls_ctr_drbg_random, &ptls_mbedtls_ctr_drbg);
    }
}
#endif

static int ptls_mbedtls_exchange_id_from_tls(int tls_id)
{
    int mbedtls_id = MBEDTLS_ECP_DP_NONE;
    switch (tls_id) {
    case PTLS_GROUP_SECP256R1:
        mbedtls_id = MBEDTLS_ECP_DP_SECP256R1;
        break;
    case PTLS_GROUP_SECP384R1:
        mbedtls_id = MBEDTLS_ECP_DP_SECP384R1;
        break;
    case PTLS_GROUP_SECP521R1:
        mbedtls_id = MBEDTLS_ECP_DP_SECP521R1;
        break;
    case PTLS_GROUP_X25519:
        mbedtls_id = MBEDTLS_ECP_DP_CURVE25519;
        break;
    case PTLS_GROUP_X448:
        mbedtls_id = MBEDTLS_ECP_DP_CURVE448;
        break;
    default:
        break;
    }
    return mbedtls_id;
}

#if 0
static int ptls_mbedtls_ecdh_on_exchange(
    struct st_ptls_key_exchange_context_t** keyex, int release, ptls_iovec_t* secret, ptls_iovec_t peerkey)
{

}

static int ptls_mbedtls_ecdh_create(const struct st_ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **keyex)
{
    /* TODO: simplify */
    struct ptls_mbedtls_ecdh_key_exchange_context_t *ctx;
    int ret = 0;
    int mbedtls_id = ptls_mbedtls_exchange_id_from_tls(algo->id);

    if (mbedtls_id == MBEDTLS_ECP_DP_NONE) {
        return PTLS_ERROR_NOT_AVAILABLE;
    }
    if ((ctx = (struct ptls_mbedtls_ecdh_key_exchange_context_t*)malloc(sizeof(*ctx))) == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    ctx->super = (ptls_key_exchange_context_t){algo, ptls_iovec_init(ctx->pub, sizeof(ctx->pub)), ptls_mbedtls_ecdh_on_exchange};
    ret = mbedtls_ecdh_setup(&ctx->ecdh_ctx, mbedtls_id);
    ctx->pub[0] = TYPE_MBEDTLS_ECDH_UNCOMPRESSED_PUBLIC_KEY;




    return 0;







    if (ret == 0) {
        ret = mbedtls_ecdh_make_params(&ctx->ecdh_ctx, &cli_olen, cli_to_srv,
            sizeof(cli_to_srv),
            mbedtls_ctr_drbg_random, &ptls_mbedtls_ctr_drbg);
    }
}
#endif