/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
#include <ippcp.h>
#include "picotls.h"
#include "picotls/ipp-crypto.h"

struct aead_context {
    ptls_aead_context_t super;
    IppsAES_GCMState *ipp;
};

static void aes128gcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;

    if (ctx->ipp != NULL) {
        ippsAES_GCMReset(ctx->ipp);
        free(ctx->ipp);
        ctx->ipp = NULL;
    }
}

static void aes128gcm_encrypt_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;
    IppStatus ret;

    ret = ippsAES_GCMStart(iv, PTLS_AESGCM_IV_SIZE, aad, aadlen, ctx->ipp);
    assert(ret == ippStsNoErr);
}

static size_t aes128gcm_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;
    IppStatus ret;

    ret = ippsAES_GCMEncrypt(input, output, inlen, ctx->ipp);
    assert(ret == ippStsNoErr);

    return inlen;
}

static size_t aes128gcm_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;
    IppStatus ret;

    ret = ippsAES_GCMGetTag(output, PTLS_AESGCM_TAG_SIZE, ctx->ipp);
    assert(ret == ippStsNoErr);

    return PTLS_AESGCM_TAG_SIZE;
}

static size_t aes128gcm_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                                const void *aad, size_t aadlen)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;
    uint8_t tag[PTLS_AESGCM_TAG_SIZE];
    IppStatus ret;

    if (inlen < PTLS_AESGCM_TAG_SIZE)
        return SIZE_MAX;

    ret = ippsAES_GCMStart(iv, PTLS_AESGCM_IV_SIZE, aad, aadlen, ctx->ipp);
    assert(ret == ippStsNoErr);
    ret = ippsAES_GCMDecrypt(input, output, inlen - PTLS_AESGCM_TAG_SIZE, ctx->ipp);
    assert(ret == ippStsNoErr);
    ret = ippsAES_GCMGetTag(tag, PTLS_AESGCM_TAG_SIZE, ctx->ipp);
    assert(ret == ippStsNoErr);

    if (!ptls_mem_equal(input + inlen - PTLS_AESGCM_TAG_SIZE, tag, PTLS_AESGCM_TAG_SIZE))
        return SIZE_MAX;
    return inlen - PTLS_AESGCM_TAG_SIZE;
}

static int aes128gcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key)
{
    struct aead_context *ctx = (struct aead_context *)_ctx;
    int ippStateSize, ret;

    ctx->super.dispose_crypto = aes128gcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = aes128gcm_encrypt_init;
        ctx->super.do_encrypt_update = aes128gcm_encrypt_update;
        ctx->super.do_encrypt_final = aes128gcm_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aes128gcm_decrypt;
    }
    ctx->ipp = NULL;

    if (ippsAES_GCMGetSize(&ippStateSize) != ippStsNoErr) {
        ret = PTLS_ERROR_LIBRARY;
        goto Error;
    }
    if ((ctx->ipp = malloc(ippStateSize)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Error;
    }
    if (ippsAES_GCMInit(key, PTLS_AES128_KEY_SIZE, ctx->ipp, ippStateSize) != ippStsNoErr) {
        ret = PTLS_ERROR_LIBRARY;
        goto Error;
    }

    return 0;

Error:
    aes128gcm_dispose_crypto(&ctx->super);
    return ret;
}

extern ptls_cipher_algorithm_t ptls_openssl_aes128ctr, ptls_openssl_aes128ecb;

ptls_aead_algorithm_t ptls_ipp_aes128gcm = {
    "AES128-GCM",        &ptls_openssl_aes128ctr, &ptls_openssl_aes128ecb,     PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,    sizeof(struct aead_context), aes128gcm_setup_crypto};
