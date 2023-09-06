#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

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
* TODO: develop shim for other hash methods besides SHA256
*/

typedef struct st_ptls_mbedtls_sha256_ctx_t {
    ptls_hash_context_t super;
    mbedtls_sha256_context mctx;
} ptls_mbedtls_sha256_ctx_t;

static void ptls_mbedtls_sha256_update(struct st_ptls_hash_context_t* _ctx, const void* src, size_t len)
{
    ptls_mbedtls_sha256_ctx_t* ctx = (ptls_mbedtls_sha256_ctx_t*)_ctx;

    (void)mbedtls_sha256_update(&ctx->mctx, (const uint8_t*)src, len);
}

static void ptls_mbedtls_sha256_final(struct st_ptls_hash_context_t* _ctx, void* md, ptls_hash_final_mode_t mode);

static struct st_ptls_hash_context_t* ptls_mbedtls_sha256_clone(struct st_ptls_hash_context_t* _src)
{
    ptls_mbedtls_sha256_ctx_t* ctx = (ptls_mbedtls_sha256_ctx_t*)malloc(sizeof(ptls_mbedtls_sha256_ctx_t));

    if (ctx != NULL) {
        ptls_mbedtls_sha256_ctx_t* src = (ptls_mbedtls_sha256_ctx_t*)_src;
        memset(&ctx->mctx, 0, sizeof(mbedtls_sha256_context));
        ctx->super.clone_ = ptls_mbedtls_sha256_clone;
        ctx->super.update = ptls_mbedtls_sha256_update;
        ctx->super.final = ptls_mbedtls_sha256_final;
        mbedtls_sha256_clone(&ctx->mctx, &src->mctx);
    }
    return (ptls_hash_context_t*)ctx;
}

static void ptls_mbedtls_sha256_final(struct st_ptls_hash_context_t* _ctx, void* md, ptls_hash_final_mode_t mode)
{
    ptls_mbedtls_sha256_ctx_t* ctx = (ptls_mbedtls_sha256_ctx_t*)_ctx;

    if (mode == PTLS_HASH_FINAL_MODE_SNAPSHOT) {
        struct st_ptls_hash_context_t* cloned = ptls_mbedtls_sha256_clone(_ctx);

        if (cloned != NULL) {
            ptls_mbedtls_sha256_final(cloned, md, PTLS_HASH_FINAL_MODE_FREE);
        }
    } else {
        if (md != NULL) {
            (void)mbedtls_sha256_finish(&ctx->mctx, (uint8_t*)md);
        }

        if (mode == PTLS_HASH_FINAL_MODE_FREE) {
            mbedtls_sha256_free(&ctx->mctx);
            free(ctx);
        }
        else {
            /* if mode = reset, reset the context */
            mbedtls_sha256_init(&ctx->mctx);
            mbedtls_sha256_starts(&ctx->mctx, 0 /* is224 = 0 */);
        }
    }
}

ptls_hash_context_t* ptls_mbedtls_sha256_create(void)
{
    ptls_mbedtls_sha256_ctx_t* ctx = (ptls_mbedtls_sha256_ctx_t*)malloc(sizeof(ptls_mbedtls_sha256_ctx_t));

    if (ctx != NULL) {
        memset(&ctx->mctx, 0, sizeof(mbedtls_sha256_context));
        ctx->super.clone_ = ptls_mbedtls_sha256_clone;
        ctx->super.update = ptls_mbedtls_sha256_update;
        ctx->super.final = ptls_mbedtls_sha256_final;
        if (mbedtls_sha256_starts(&ctx->mctx, 0 /* is224 = 0 */) != 0) {
            free(ctx);
            ctx = NULL;
        }
    }
    return (ptls_hash_context_t*)ctx;
}

ptls_hash_algorithm_t ptls_mbedtls_sha256 = {"sha256", PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, ptls_mbedtls_sha256_create,
PTLS_ZERO_DIGEST_SHA256};


/* definitions for symmetric crypto algorithms. 
* Each algorithm (ECB or CTR) is represented by an "algorithm"
* entry in which the 'setup" function is used to initialize
* The "setup" function creates an object of type
* ptls_cipher_context_t, with three function pointers:
* 
*   void (*do_dispose)(struct st_ptls_cipher_context_t *ctx);
*   void (*do_init)(struct st_ptls_cipher_context_t *ctx, const void *iv);
*   void (*do_transform)(struct st_ptls_cipher_context_t *ctx, void *output, const void *input, size_t len);
* 
* "do_init" sets the IV value. In CTR mode, this is the nonce value, which
* will be incremented after each block. In CTR mode, this also sets the 
* "stream block".
* 
 */
struct ptls_mbedtls_symmetric_param_t {
    uint8_t iv[PTLS_MAX_IV_SIZE];
    uint8_t *key_object;
    int is_enc;
};

struct st_ptls_mbedtls_aes_context_t {
    ptls_cipher_context_t super;
    mbedtls_aes_context aes_ctx;
    uint8_t nonce_counter[16];
    uint8_t stream_block[16];
    int is_enc; /* MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT */
};

static void ptls_mbedtls_aes_ctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;

    if (iv == NULL) {
        memset(ctx->nonce_counter, 0, 16);
    }
    else {
        memcpy(ctx->nonce_counter, iv, 16);
    }
    memset(ctx->stream_block, 0, 16);
}

static void ptls_mbedtls_aes_ecb_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;

    /* Call the encryption */
    if (mbedtls_aes_crypt_ecb(&ctx->aes_ctx, ctx->is_enc, (const uint8_t*)input, (uint8_t*)output) != 0) {
        memset(output, 0, len);
    }
}

static void ptls_mbedtls_aes_ctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    size_t nc_off = 0;

    if (mbedtls_aes_crypt_ctr(&ctx->aes_ctx, len, &nc_off, ctx->nonce_counter, ctx->stream_block,
        (const uint8_t*)input, (uint8_t*)output) != 0) {
        memset(output, 0, len);
    }
}

static void ptls_mbedtls_aes_ctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    mbedtls_aes_free(&ctx->aes_ctx);
}

static int ptls_mbedtls_cipher_setup_crypto_aes(ptls_cipher_context_t* _ctx, int is_enc, const void* key, unsigned int keybits)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    int ret = 0;

    memset(ctx->nonce_counter, 0, 16);
    memset(ctx->stream_block, 0, 16);

    ctx->super.do_dispose = ptls_mbedtls_aes_ctr_dispose;
    ctx->super.do_init = ptls_mbedtls_aes_ctr_init;
    ctx->super.do_transform = NULL;

    mbedtls_aes_init(&ctx->aes_ctx);
    if (is_enc) {
        ret = mbedtls_aes_setkey_enc(&ctx->aes_ctx, key, keybits);
        ctx->is_enc = MBEDTLS_AES_ENCRYPT;
    }
    else {
        ret = mbedtls_aes_setkey_dec(&ctx->aes_ctx, key, keybits);
        ctx->is_enc = MBEDTLS_AES_DECRYPT;
    }

    return ret;

}

static int ptls_mbedtls_cipher_setup_crypto_aes128_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    int ret = ptls_mbedtls_cipher_setup_crypto_aes(_ctx, is_enc, key, 128);

    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_aes_ecb_transform;
    }

    return ret;
}

static int ptls_mbedtls_cipher_setup_crypto_aes128_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(is_enc);
#endif
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    int ret = ptls_mbedtls_cipher_setup_crypto_aes(_ctx, 1, key, 128); /* No difference between CTR encrypt and decrypt */

    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_aes_ctr_transform;
    }

    return ret;
}


static int ptls_mbedtls_cipher_setup_crypto_aes256_ecb(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    int ret = ptls_mbedtls_cipher_setup_crypto_aes(_ctx, is_enc, key, 256);

    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_aes_ecb_transform;
    }

    return ret;
}

static int ptls_mbedtls_cipher_setup_crypto_aes256_ctr(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(is_enc);
#endif
    struct st_ptls_mbedtls_aes_context_t *ctx = (struct st_ptls_mbedtls_aes_context_t *)_ctx;
    int ret = ptls_mbedtls_cipher_setup_crypto_aes(_ctx, 1, key, 256); /* No difference between CTR encrypt and decrypt */

    if (ret == 0) {
        ctx->super.do_transform = ptls_mbedtls_aes_ctr_transform;
    }

    return ret;
}

ptls_cipher_algorithm_t ptls_mbedtls_aes128ecb = {
    "AES128-ECB",
    PTLS_AES128_KEY_SIZE,
    PTLS_AES_BLOCK_SIZE,
    0 /* iv size */,
    sizeof(struct st_ptls_mbedtls_aes_context_t),
    ptls_mbedtls_cipher_setup_crypto_aes128_ecb};

ptls_cipher_algorithm_t ptls_mbedtls_aes256ecb = {"AES256-ECB",
PTLS_AES256_KEY_SIZE,
PTLS_AES_BLOCK_SIZE,
0 /* iv size */,
sizeof(struct st_ptls_mbedtls_aes_context_t),
ptls_mbedtls_cipher_setup_crypto_aes256_ecb};

ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr = {"AES128-CTR",
PTLS_AES128_KEY_SIZE,
PTLS_AES_BLOCK_SIZE,
0 /* iv size */,
sizeof(struct st_ptls_mbedtls_aes_context_t),
ptls_mbedtls_cipher_setup_crypto_aes128_ctr};

ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr = {"AES256-CTR",
PTLS_AES256_KEY_SIZE,
PTLS_AES_BLOCK_SIZE,
0 /* iv size */,
sizeof(struct st_ptls_mbedtls_aes_context_t),
ptls_mbedtls_cipher_setup_crypto_aes256_ctr};

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
* TODO: declare other lagorithms besides AES128_GCM
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
    &ptls_mbedtls_aes128ecb,
    &ptls_mbedtls_aes128ctr,
    PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE,
    PTLS_AESGCM_TAG_SIZE,
    {PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE},
    0,
    0,
    sizeof(struct ptls_mbedtls_aead_context_t),
    ptls_mbedtls_aead_setup_crypto
};
