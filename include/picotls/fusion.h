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
#ifndef picotls_fusion_h
#define picotls_fusion_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <emmintrin.h>
#include "../picotls.h"

#define PTLS_FUSION_AESGCM_ROUNDS 10 /* TODO support AES256 */

typedef struct ptls_fusion_aesecb_context {
    __m128i keys[PTLS_FUSION_AESGCM_ROUNDS + 1];
} ptls_fusion_aesecb_context_t;

typedef struct ptls_fusion_aesgcm_context ptls_fusion_aesgcm_context_t;

void ptls_fusion_aesecb_init(ptls_fusion_aesecb_context_t *ctx, const void *key);
void ptls_fusion_aesecb_dispose(ptls_fusion_aesecb_context_t *ctx);

/**
 * Creates an AES-GCM context.
 * @param key       the AES key (128 bits)
 * @param max_size  maximum size of the record (i.e. AAD + encrypted payload)
 */
ptls_fusion_aesgcm_context_t *ptls_fusion_aesgcm_create(const void *key, size_t max_size);
/**
 * Destroys an AES-GCM context.
 */
void ptls_fusion_aesgcm_destroy(ptls_fusion_aesgcm_context_t *ctx);
/**
 * Encrypts an AEAD block, and in parallel, optionally encrypts one block using AES-ECB.
 * @param iv       initialization vector of 12 bytes
 * @param aad      AAD
 * @param aadlen   size of AAD
 * @param dst      output buffer
 * @param src      payload to be encrypted
 * @param srclen   size of the payload to be encrypted
 * @param suppkey  (optional) points to an AES-ECB context used for generating suppvec
 * @param suppvec  (optional) vector to be encrypted using suppkey
 */
void ptls_fusion_aesgcm_encrypt(ptls_fusion_aesgcm_context_t *ctx, const void *iv, const void *_aad, size_t aadlen, void *dst,
                                const void *src, size_t srclen, ptls_fusion_aesecb_context_t *suppkey, void *suppvec);
/**
 * Decrypts an AEAD block, an in parallel, optionally encrypts one block using AES-ECB.
 * @param iv       initialization vector of 12 bytes
 * @param aad      AAD
 * @param aadlen   size of AAD
 * @param dst      output buffer
 * @param src      payload to be encrypted
 * @param srclen   size of the payload to be decrypted
 * @param tag      the AEAD tag being received from peer
 * @param suppkey  (optional) points to an AES-ECB context used for generating suppvec
 * @param suppvec  (optional) vector to be encrypted using suppkey
 */
int ptls_fusion_aesgcm_decrypt(ptls_fusion_aesgcm_context_t *ctx, const void *iv, const void *_aad, size_t aadlen, void *dst,
                               const void *src, size_t srclen, const void *tag, ptls_fusion_aesecb_context_t *suppkey,
                               void *suppvec);

extern ptls_aead_algorithm_t ptls_fusion_aes128gcm;

#ifdef __cplusplus
}
#endif

#endif
