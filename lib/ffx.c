/*
 * Copyright (c) 2016 Christian Huitema <huitema@huitema.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"
#include "picotls/minicrypto.h"
#include "picotls/ffx.h"

ptls_ffx_state_t *ptls_ffx_get_context(char const *alg_name, int nb_rounds, const void *mask, size_t len, void *key)
{
    ptls_ffx_state_t *ctx = NULL;
    ptls_cipher_context_t *enc_ctx = NULL;

    if (len <= 32) {
        /* len must be lower than 32 */

        if (strcmp(alg_name, "CHACHA20") == 0) {
            enc_ctx = ptls_cipher_new(&ptls_minicrypto_chacha20, 1, key);
        } else if (strcmp(alg_name, "AES128") == 0 || strcmp(alg_name, "AES128-CTR") == 0) {
            enc_ctx = ptls_cipher_new(&ptls_minicrypto_aes128ctr, 1, key);
        }
    }

    if (enc_ctx != NULL) {
        ctx = (ptls_ffx_state_t *)malloc(sizeof(ptls_ffx_state_t));
        if (ctx == NULL) {
            ptls_cipher_free(enc_ctx);
            enc_ctx = NULL;
        }
    }

    if (ctx != NULL) {
        ctx->enc_ctx = enc_ctx;
        ctx->nb_rounds = nb_rounds;
        ctx->len = len;
        ctx->nb_left = (int)len / 2;
        ctx->nb_right = (int)len - ctx->nb_left;
        if (mask != NULL) {
            /* Split the mask in two halves */
            memcpy(ctx->mask_left, mask, ctx->nb_left);
            memcpy(ctx->mask_right, ((uint8_t *)mask) + ctx->nb_left, ctx->nb_right);
            memset(ctx->mask_left + ctx->nb_left, 0, 16 - ctx->nb_left);
            memset(ctx->mask_right + ctx->nb_right, 0, 16 - ctx->nb_right);
        } else {
            memset(ctx->mask_left, 0xFF, 16);
            memset(ctx->mask_right, 0xFF, 16);
        }
    }

    return ctx;
}

void ptls_ffx_delete_context(ptls_ffx_state_t *ctx)
{
    ptls_cipher_free(ctx->enc_ctx);
    free(ctx);
}

void ptls_ffx_encrypt(ptls_ffx_state_t *ctx, void *output, const void *input, size_t len)
{
    uint8_t left[16], right[16], confusion[32];
    uint8_t zero16[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /* len must match context definition */
    if (len != ctx->len) {
        return;
    }
    /* Split the input in two halves */
    memcpy(left, input, ctx->nb_left);
    memcpy(right, ((uint8_t *)input) + ctx->nb_left, ctx->nb_right);
    memset(left + ctx->nb_left, 0, 16 - ctx->nb_left);
    memset(right + ctx->nb_right, 0, 16 - ctx->nb_right);

    /* Feistel construct, using the specified algorithm as S-Box */
    for (int i = 0; i < ctx->nb_rounds; i += 2) {
        /* Each pass encrypts a zero field with a cipher using one
         * half of the message as IV. This construct lets us use
         * either AES or chacha 20 */
        ptls_cipher_init(ctx->enc_ctx, right);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        /* We use a mask to guarantee
         * that some bits are unchanged */
        for (int j = 0; j < ctx->nb_left; j++) {
            left[j] ^= (confusion[j] & ctx->mask_left[j]);
        }

        memset(confusion, 0, 16);
        ptls_cipher_init(ctx->enc_ctx, left);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (int j = 0; j < ctx->nb_right; j++) {
            right[j] ^= (confusion[j] & ctx->mask_right[j]);
        }
    }

    /* After enough passes, we have a very strong length preserving
     * encryption, only that many times slower than the underlying
     * algorithm. We copy the result to the output */
    memcpy(output, left, ctx->nb_left);
    memcpy(((uint8_t *)output) + ctx->nb_left, right, ctx->nb_right);
}

void ptls_ffx_decrypt(ptls_ffx_state_t *ctx, void *output, const void *input, size_t len)
{
    uint8_t left[16], right[16], confusion[16];
    uint8_t zero16[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /* len must be lower than 31 */
    if (len != ctx->len) {
        return;
    }

    /* Split the input in two halves */
    memcpy(left, input, ctx->nb_left);
    memcpy(right, ((uint8_t *)input) + ctx->nb_left, ctx->nb_right);
    memset(left + ctx->nb_left, 0, 16 - ctx->nb_left);
    memset(right + ctx->nb_right, 0, 16 - ctx->nb_right);

    /* Feistel construct, using the specified algorithm as S-Box,
     * in the opposite order of the encryption */

    for (int i = 0; i < ctx->nb_rounds; i += 2) {
        /* Each pass encrypts a zero field with a cipher using one
         * half of the message as IV. This construct lets us use
         * either AES or chacha 20 */
        ptls_cipher_init(ctx->enc_ctx, left);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (int j = 0; j < ctx->nb_right; j++) {
            right[j] ^= (confusion[j] & ctx->mask_right[j]);
        }
        ptls_cipher_init(ctx->enc_ctx, right);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        /* We could use a mask to guarantee
         * that some bits are unchanged */
        for (int j = 0; j < ctx->nb_left; j++) {
            left[j] ^= (confusion[j] & ctx->mask_left[j]);
        }
    }

    /* Copy the decrypted result to the output */
    memcpy(output, left, ctx->nb_left);
    memcpy(((uint8_t *)output) + ctx->nb_left, right, ctx->nb_right);
}