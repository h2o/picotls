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
#include <stdlib.h>
#include "aes.h"
#include "modes.h"
#include "sha2.h"
#include "picotls.h"
#include "picotls/minicrypto.h"

struct aesecb_context_t {
    ptls_cipher_context_t super;
    cf_aes_context aes;
};

static void aesecb_dispose(ptls_cipher_context_t *_ctx)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void aesecb_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    assert(len % AES_BLOCKSZ == 0);
    cf_aes_encrypt(&ctx->aes, input, output);
}

static void aesecb_decrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    assert(len % AES_BLOCKSZ == 0);
    cf_aes_decrypt(&ctx->aes, input, output);
}

static int aesecb_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct aesecb_context_t *ctx = (struct aesecb_context_t *)_ctx;
    ctx->super.do_dispose = aesecb_dispose;
    ctx->super.do_init = NULL;
    ctx->super.do_transform = is_enc ? aesecb_encrypt : aesecb_decrypt;
    cf_aes_init(&ctx->aes, key, key_size);
    return 0;
}

static int aes128ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesecb_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aes256ecb_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesecb_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

struct aesctr_context_t {
    ptls_cipher_context_t super;
    cf_aes_context aes;
    cf_ctr ctr;
};

static void aesctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void aesctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    cf_ctr_init(&ctx->ctr, &cf_aes, &ctx->aes, iv);
}

static void aesctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    cf_ctr_cipher(&ctx->ctr, input, output, len);
}

static int aesctr_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct aesctr_context_t *ctx = (struct aesctr_context_t *)_ctx;
    ctx->super.do_dispose = aesctr_dispose;
    ctx->super.do_init = aesctr_init;
    ctx->super.do_transform = aesctr_transform;
    cf_aes_init(&ctx->aes, key, key_size);
    return 0;
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

struct aesgcm_context_t {
    ptls_aead_context_t super;
    cf_aes_context aes;
    cf_gcm_ctx gcm;
};

static void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory((uint8_t *)ctx + sizeof(ctx->super), sizeof(*ctx) - sizeof(ctx->super));
}

static void aesgcm_encrypt_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    cf_gcm_encrypt_init(&cf_aes, &ctx->aes, &ctx->gcm, aad, aadlen, iv, PTLS_AESGCM_IV_SIZE);
}

static size_t aesgcm_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    cf_gcm_encrypt_update(&ctx->gcm, input, inlen, output);
    return inlen;
}

static size_t aesgcm_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    cf_gcm_encrypt_final(&ctx->gcm, output, PTLS_AESGCM_TAG_SIZE);
    return PTLS_AESGCM_TAG_SIZE;
}

static size_t aesgcm_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                             const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    if (inlen < PTLS_AESGCM_TAG_SIZE)
        return SIZE_MAX;
    size_t tag_offset = inlen - PTLS_AESGCM_TAG_SIZE;

    if (cf_gcm_decrypt(&cf_aes, &ctx->aes, input, tag_offset, aad, aadlen, iv, PTLS_AESGCM_IV_SIZE, (uint8_t *)input + tag_offset,
                       PTLS_AESGCM_TAG_SIZE, output) != 0)
        return SIZE_MAX;

    return tag_offset;
}

static int aead_aesgcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = aesgcm_encrypt_init;
        ctx->super.do_encrypt_update = aesgcm_encrypt_update;
        ctx->super.do_encrypt_final = aesgcm_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aesgcm_decrypt;
    }

    cf_aes_init(&ctx->aes, key, key_size);
    return 0;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

ptls_define_hash(sha256, cf_sha256_context, cf_sha256_init, cf_sha256_update, cf_sha256_digest_final);
ptls_define_hash(sha384, cf_sha512_context, cf_sha384_init, cf_sha384_update, cf_sha384_digest_final);

ptls_hash_algorithm_t ptls_minicrypto_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, sha256_create,
                                                PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_minicrypto_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, sha384_create,
                                                PTLS_ZERO_DIGEST_SHA384};

ptls_cipher_algorithm_t ptls_minicrypto_aes128ecb = {
    "AES128-ECB",          PTLS_AES128_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct aesecb_context_t),
    aes128ecb_setup_crypto};
ptls_cipher_algorithm_t ptls_minicrypto_aes128ctr = {
    "AES128-CTR",          PTLS_AES128_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct aesctr_context_t),
    aes128ctr_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_aes128gcm = {
    "AES128-GCM",        &ptls_minicrypto_aes128ctr, &ptls_minicrypto_aes128ecb,      PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes128gcm_setup_crypto};
ptls_cipher_algorithm_t ptls_minicrypto_aes256ecb = {
    "AES128-ECB",          PTLS_AES256_KEY_SIZE, PTLS_AES_BLOCK_SIZE, 0 /* iv size */, sizeof(struct aesecb_context_t),
    aes256ecb_setup_crypto};
ptls_cipher_algorithm_t ptls_minicrypto_aes256ctr = {
    "AES256-CTR",          PTLS_AES256_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct aesctr_context_t),
    aes256ctr_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_aes256gcm = {
    "AES256-GCM",        &ptls_minicrypto_aes256ctr, &ptls_minicrypto_aes256ecb,      PTLS_AES256_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes256gcm_setup_crypto};
ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_minicrypto_aes128gcm,
                                                       &ptls_minicrypto_sha256};
ptls_cipher_suite_t ptls_minicrypto_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_minicrypto_aes256gcm,
                                                       &ptls_minicrypto_sha384};
