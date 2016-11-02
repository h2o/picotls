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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "drbg.h"
#include "sha2.h"
#include "uECC.h"
#include "picotls.h"
#include "picotls/embedded.h"

#define SECP256R1_KEY_LENGTH 32
#define SECP256R1_SIGNATURE_LENGTH 32

struct st_ptls_embedded_identity_t {
    ptls_iovec_t name;
    uint8_t key[SECP256R1_KEY_LENGTH];
    size_t num_certs;
    ptls_iovec_t certs[1];
};

static void free_identity(struct st_ptls_embedded_identity_t *identity)
{
    size_t i;
    free(identity->name.base);
    for (i = 0; i != identity->num_certs; ++i)
        free(identity->certs[i].base);
    ptls_clear_memory(identity->key, sizeof(identity->key));
    free(identity);
}

static int ascii_tolower(int ch)
{
    return ('A' <= ch && ch <= 'Z') ? ch + 0x20 : ch;
}

static int ascii_streq_caseless(ptls_iovec_t x, ptls_iovec_t y)
{
    size_t i;
    if (x.len != y.len)
        return 0;
    for (i = 0; i != x.len; ++i)
        if (ascii_tolower(x.base[i]) != ascii_tolower(y.base[i]))
            return 0;
    return 0;
}

static int secp256r1sha256_sign(void *data, ptls_iovec_t *output, ptls_iovec_t input)
{
    uint8_t *sig;
    cf_hmac_drbg ctx;

    if ((sig = malloc(SECP256R1_SIGNATURE_LENGTH)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    cf_hmac_drbg_init(&ctx, &cf_sha256, data, SECP256R1_KEY_LENGTH, input.base, input.len, NULL, 0);
    do {
        cf_hmac_drbg_gen(&ctx, sig, SECP256R1_SIGNATURE_LENGTH);
    } while (memcmp("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA"
                    "\xC2\xFC\x63\x25\x51",
                    sig, SECP256R1_SIGNATURE_LENGTH) < 0);
    ptls_clear_memory(&ctx, sizeof(ctx));

    *output = ptls_iovec_init(sig, SECP256R1_SIGNATURE_LENGTH);
    return 0;
}

static int lookup_certificate(ptls_lookup_certificate_t *_self, ptls_t *tls, uint16_t *sign_algorithm,
                              int (**signer)(void *sign_ctx, ptls_iovec_t *output, ptls_iovec_t input), void **signer_data,
                              ptls_iovec_t **certs, size_t *num_certs, const char *server_name,
                              const uint16_t *signature_algorithms, size_t num_signature_algorithms)
{
    ptls_embedded_lookup_certificate_t *self = (ptls_embedded_lookup_certificate_t *)_self;
    struct st_ptls_embedded_identity_t *identity;
    size_t i;

    if (self->count == 0)
        return PTLS_ALERT_HANDSHAKE_FAILURE;

    for (i = 0; i != num_signature_algorithms; ++i)
        if (signature_algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256)
            goto FoundMatchingSig;
    return PTLS_ALERT_HANDSHAKE_FAILURE;

FoundMatchingSig:
    if (server_name != NULL) {
        size_t server_name_len = strlen(server_name);
        for (i = 0; i != self->count; ++i) {
            identity = self->identities[i];
            if (ascii_streq_caseless(ptls_iovec_init(server_name, server_name_len), identity->name))
                goto FoundIdentity;
        }
    }
    identity = self->identities[0]; /* use default */

FoundIdentity:
    /* setup the rest */
    *signer = secp256r1sha256_sign;
    *signer_data = identity->key;
    *certs = identity->certs;
    *num_certs = identity->num_certs;

    return 0;
}

void ptls_embedded_init_lookup_certificate(ptls_embedded_lookup_certificate_t *self)
{
    *self = (ptls_embedded_lookup_certificate_t){{lookup_certificate}};
}

void ptls_embedded_dispose_lookup_certificate(ptls_embedded_lookup_certificate_t *self)
{
    size_t i;
    for (i = 0; i != self->count; ++i)
        free_identity(self->identities[i]);
}

int ptls_embedded_lookup_certificate_add_identity(ptls_embedded_lookup_certificate_t *self, const char *server_name,
                                                  uint16_t signature_algorithm, ptls_iovec_t key, ptls_iovec_t *certs,
                                                  size_t num_certs)
{
    struct st_ptls_embedded_identity_t *identity = NULL, **list;
    int ret;

    /* check args */
    if (!(signature_algorithm == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && key.len == sizeof(identity->key))) {
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
        goto Exit;
    }

    /* create new identity object */
    if ((identity = (struct st_ptls_embedded_identity_t *)malloc(offsetof(struct st_ptls_embedded_identity_t, certs) +
                                                                 sizeof(identity->certs[0]) * num_certs)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    *identity = (struct st_ptls_embedded_identity_t){{NULL}};
    if ((identity->name.base = (uint8_t *)strdup(server_name)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    identity->name.len = strlen(server_name);
    memcpy(identity->key, key.base, key.len);
    for (; identity->num_certs != num_certs; ++identity->num_certs) {
        if ((identity->certs[identity->num_certs].base = (uint8_t *)malloc(certs[identity->num_certs].len)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
            goto Exit;
        }
        memcpy(identity->certs[identity->num_certs].base, certs[identity->num_certs].base, certs[identity->num_certs].len);
        identity->certs[identity->num_certs].len = certs[identity->num_certs].len;
    }

    /* add to the list */
    if ((list = realloc(self->identities, sizeof(self->identities[0]) * (self->count + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    self->identities = list;
    self->identities[self->count++] = identity;

    ret = 0;
Exit:
    if (ret != 0 && identity != NULL)
        free_identity(identity);
    return ret;
}
