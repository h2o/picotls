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
#include <sodium.h>
#include "picotls.h"
#include "picotls/sodium.h"

void ptls_sodium_random_bytes(void *buf, size_t len)
{
    randombytes(buf, len);
}

struct st_x25519_key_exhchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[crypto_box_SECRETKEYBYTES];
    uint8_t pub[crypto_box_PUBLICKEYBYTES];
};

static void x25519_create_keypair(uint8_t *priv, uint8_t *pub)
{
    randombytes_buf(priv, crypto_box_SECRETKEYBYTES);
    crypto_scalarmult_base(pub, priv);
}

static int x25519_derive_secret(ptls_iovec_t *secret, const uint8_t *clientpriv, const uint8_t *clientpub,
                                const uint8_t *serverpriv, const uint8_t *serverpub)
{
    uint8_t q[crypto_scalarmult_BYTES];
    crypto_generichash_state h;
    int ret;

    if (crypto_scalarmult(q, clientpriv != NULL ? clientpriv : serverpriv, clientpriv != NULL ? serverpub : clientpub) != 0) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    if ((secret->base = malloc(crypto_generichash_BYTES)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    secret->len = crypto_generichash_BYTES;

    crypto_generichash_init(&h, NULL, 0U, crypto_generichash_BYTES);
    crypto_generichash_update(&h, q, sizeof(q));
    crypto_generichash_update(&h, clientpub, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_update(&h, serverpub, crypto_box_PUBLICKEYBYTES);
    crypto_generichash_final(&h, secret->base, secret->len);

    ret = 0;
Exit:
    ptls_clear_memory(q, sizeof(q));
    return ret;
}

static int x25519_on_exchange(ptls_key_exchange_context_t *_ctx, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x25519_key_exhchange_t *ctx = (struct st_x25519_key_exhchange_t *)_ctx;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != crypto_box_PUBLICKEYBYTES) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = x25519_derive_secret(secret, ctx->priv, ctx->pub, NULL, peerkey.base);

Exit:
    ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
    free(ctx);
    return ret;
}

static int x25519_create_key_exchange(ptls_key_exchange_context_t **_ctx, ptls_iovec_t *pubkey)
{
    struct st_x25519_key_exhchange_t *ctx;

    if ((ctx = (struct st_x25519_key_exhchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){x25519_on_exchange};
    x25519_create_keypair(ctx->priv, ctx->pub);

    *_ctx = &ctx->super;
    *pubkey = ptls_iovec_init(ctx->pub, sizeof(ctx->pub));
    return 0;
}

static int x25519_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    uint8_t priv[crypto_box_SECRETKEYBYTES], *pub = NULL;
    int ret;

    if (peerkey.len != crypto_box_PUBLICKEYBYTES) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(crypto_box_PUBLICKEYBYTES)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    x25519_create_keypair(priv, pub);
    if ((ret = x25519_derive_secret(secret, NULL, peerkey.base, priv, pub)) != 0)
        goto Exit;

    *pubkey = ptls_iovec_init(pub, crypto_box_PUBLICKEYBYTES);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (pub != NULL && ret != 0)
        ptls_clear_memory(pub, sizeof(pub));
    return ret;
}

ptls_key_exchange_algorithm_t ptls_sodium_x25519 = {PTLS_GROUP_SECP256R1, x25519_create_key_exchange, x25519_key_exchange};
ptls_key_exchange_algorithm_t *ptls_sodium_key_exchanges[] = {&ptls_sodium_x25519, NULL};
