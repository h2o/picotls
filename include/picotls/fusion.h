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

#include "../picotls.h"

#define PTLS_FUSION_AESGCM_ROUNDS 10 /* TODO support AES256 */

typedef struct ptls_fusion_aesgcm_context_t {
    __m128i keys[PTLS_FUSION_AESGCM_ROUNDS + 1];
    struct {
        __m128i H;
        __m128i r;
    } ghash[6];
} ptls_fusion_aesgcm_context_t;

void ptls_fusion_aesgcm_init(ptls_fusion_aesgcm_context_t *ctx, const void *key);
void ptls_fusion_aesgcm_dispose(ptls_fusion_aesgcm_context_t *ctx);

extern ptls_aead_algorithm_t ptls_fusion_aes128gcm;

#ifdef __cplusplus
}
#endif

#endif
