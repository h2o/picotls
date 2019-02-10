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

int ptls_ffx_setup_crypto(ptls_cipher_context_t *_ctx, char const *alg_name, int is_enc, int nb_rounds, size_t bit_length,
                                     void *key)
{
    int ret = 0;
    ptls_ffx_state_t *ctx = (ptls_ffx_state_t *)_ctx;
    ptls_cipher_context_t *enc_ctx = NULL;
    size_t len = (bit_length + 7) / 8;
    uint8_t last_byte_mask[8] = { 
        0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};

    if (len <= 32) {
        /* len must be lower than 32 */

        if (strcmp(alg_name, "CHACHA20") == 0) {
            enc_ctx = ptls_cipher_new(&ptls_minicrypto_chacha20, 1, key);
        } else if (strcmp(alg_name, "AES128") == 0 || strcmp(alg_name, "AES128-CTR") == 0) {
            enc_ctx = ptls_cipher_new(&ptls_minicrypto_aes128ctr, 1, key);
        }
        if (enc_ctx == NULL) {
            ret = -1;
        }
    } else {
        ret = -1;
    }

    if (ret == 0) {
        ctx->enc_ctx = enc_ctx;
        ctx->nb_rounds = nb_rounds;
        ctx->byte_length = len;
        ctx->nb_left = (int)len / 2;
        ctx->nb_right = (int)len - ctx->nb_left;
        ctx->mask_last_byte = last_byte_mask[bit_length % 8];

        ctx->super.do_dispose = ptls_ffx_dispose;
        ctx->super.do_init = ptls_ffx_init;
        ctx->super.do_transform = (is_enc) ? ptls_ffx_encrypt : ptls_ffx_decrypt;
    } else {
        ptls_ffx_dispose(_ctx);
    }

    return ret;
}

void ptls_ffx_dispose(ptls_cipher_context_t *_ctx)
{
    ptls_ffx_state_t *ctx = (ptls_ffx_state_t *)_ctx;

    if (ctx->enc_ctx != NULL) {
        ptls_cipher_free(ctx->enc_ctx);
    }

    ctx->enc_ctx = NULL;
    ctx->nb_rounds = 0;
    ctx->byte_length = 0;
    ctx->nb_left = 0;
    ctx->nb_right = 0;
    ctx->mask_last_byte = 0;

    ctx->super.do_dispose = NULL;
    ctx->super.do_init = NULL;
    ctx->super.do_transform = NULL;
}

void ptls_ffx_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    ptls_ffx_state_t *ctx = (ptls_ffx_state_t *)_ctx;
    uint8_t left[16], right[16], confusion[32];
    uint8_t zero16[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t last_byte;

    /* len must match context definition */
    if (len != ctx->byte_length || len < 2) {
        return;
    }

    /* Split the input in two halves */
    memcpy(left, input, ctx->nb_left);
    memcpy(right, ((uint8_t *)input) + ctx->nb_left, ctx->nb_right);
    memset(left + ctx->nb_left, 0, 16 - ctx->nb_left);
    memset(right + ctx->nb_right, 0, 16 - ctx->nb_right);
    last_byte = right[ctx->nb_right - 1];
    right[ctx->nb_right - 1] &= ctx->mask_last_byte;

    /* Feistel construct, using the specified algorithm as S-Box */
    for (int i = 0; i < ctx->nb_rounds; i += 2) {
        /* Each pass encrypts a zero field with a cipher using one
         * half of the message as IV. This construct lets us use
         * either AES or chacha 20 */
        ptls_cipher_init(ctx->enc_ctx, right);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (size_t j = 0; j < ctx->nb_left; j++) {
            left[j] ^= confusion[j];
        }

        memset(confusion, 0, 16);
        ptls_cipher_init(ctx->enc_ctx, left);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (size_t j = 0; j < ctx->nb_right-1; j++) {
            right[j] ^= confusion[j];
        }
        right[ctx->nb_right - 1] ^= (confusion[ctx->nb_right - 1] & ctx->mask_last_byte);
    }

    /* After enough passes, we have a very strong length preserving
     * encryption, only that many times slower than the underlying
     * algorithm. We copy the result to the output */
    memcpy(output, left, ctx->nb_left);

    right[ctx->nb_right - 1] &= ctx->mask_last_byte;
    right[ctx->nb_right - 1] |= (last_byte & ~ctx->mask_last_byte);

    memcpy(((uint8_t *)output) + ctx->nb_left, right, ctx->nb_right);
}

void ptls_ffx_decrypt(ptls_cipher_context_t * _ctx, void *output, const void *input, size_t len)
{
    ptls_ffx_state_t *ctx = (ptls_ffx_state_t *)_ctx;
    uint8_t left[16], right[16], confusion[16];
    uint8_t zero16[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t last_byte;

    /* len must be lower than 31 */
    if (len != ctx->byte_length) {
        return;
    }

    /* Split the input in two halves */
    memcpy(left, input, ctx->nb_left);
    memcpy(right, ((uint8_t *)input) + ctx->nb_left, ctx->nb_right);
    memset(left + ctx->nb_left, 0, 16 - ctx->nb_left);
    memset(right + ctx->nb_right, 0, 16 - ctx->nb_right);
    last_byte = right[ctx->nb_right - 1];
    right[ctx->nb_right - 1] &= ctx->mask_last_byte;

    /* Feistel construct, using the specified algorithm as S-Box,
     * in the opposite order of the encryption */

    for (int i = 0; i < ctx->nb_rounds; i += 2) {
        /* Each pass encrypts a zero field with a cipher using one
         * half of the message as IV. This construct lets us use
         * either AES or chacha 20 */
        ptls_cipher_init(ctx->enc_ctx, left);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (size_t j = 0; j < ctx->nb_right - 1; j++) {
            right[j] ^= confusion[j];
        }
        right[ctx->nb_right - 1] ^= (confusion[ctx->nb_right - 1] & ctx->mask_last_byte);

        ptls_cipher_init(ctx->enc_ctx, right);
        ptls_cipher_encrypt(ctx->enc_ctx, confusion, zero16, 16);
        for (size_t j = 0; j < ctx->nb_left; j++) {
            left[j] ^= confusion[j];
        }
    }

    /* Copy the decrypted result to the output */
    memcpy(output, left, ctx->nb_left);

    right[ctx->nb_right - 1] &= ctx->mask_last_byte;
    right[ctx->nb_right - 1] |= (last_byte & ~ctx->mask_last_byte);

    memcpy(((uint8_t *)output) + ctx->nb_left, right, ctx->nb_right);
}

void ptls_ffx_init(struct st_ptls_cipher_context_t *ctx, const void *iv)
{
    /* TODO ! */
}
