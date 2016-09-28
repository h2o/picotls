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
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "picotls.h"

#define PTLS_MAX_RECORD_LENGTH 16384

#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 1

#define PTLS_CONTENT_TYPE_ALERT 21
#define PTLS_CONTENT_TYPE_HANDSHAKE 22
#define PTLS_CONTENT_TYPE_APPDATA 23

#define PTLS_HANDSHAKE_TYPE_CLIENT_HELLO 1
#define PTLS_HANDSHAKE_TYPE_SERVER_HELLO 2
#define PTLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET 4
#define PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST 6
#define PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS 8
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE 11
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST 13
#define PTLS_HANDSHAKE_TYPE_VERIFY 15
#define PTLS_HANDSHAKE_TYPE_FINISHED 20
#define PTLS_HANDSHAKE_TYPE_KEY_UPDATE 24

#define PTLS_EXTENSION_TYPE_SERVER_NAME 0
#define PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define PTLS_EXTENSION_TYPE_KEY_SHARE 40
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44

#define PTLS_PROTOCOL_VERSION_DRAFT16 0x7f16

struct st_ptls_iovec_t {
    uint8_t *base;
    size_t len;
};

struct st_ptls_outbuf_t {
    uint8_t *base;
    size_t capacity;
    size_t *off;
};

struct st_ptls_t {
    /**
     * the state
     */
    enum { PTLS_STATE_WAIT_CLIENT_HELLO, PTLS_STATE_WAIT_FINISHED, PTLS_STATE_APPDATA } state;
    /**
     * context
     */
    ptls_context_t *ctx;
    /**
     * record buffer
     */
    struct st_ptls_iovec_t recbuf;
    /**
     * buffer for retaining partial handshake message
     */
    struct st_ptls_iovec_t handshakebuf;
};

struct st_ptls_record_t {
    uint8_t type;
    uint16_t version;
    uint16_t length;
    const uint8_t *fragment;
};

struct st_ptls_client_hello_t {
    uint8_t random[32];
    uint16_t cipher_suite;
    struct st_ptls_iovec_t server_name;
    uint16_t negotiated_group;
    uint16_t signature_algorithm;
    struct {
        uint16_t group;
        struct st_ptls_iovec_t peer;
    } key_share;
};

static uint16_t readu16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

static uint32_t readu24(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

static int inbuf_prepare(struct st_ptls_iovec_t *vec, size_t sz)
{
    uint8_t *newp;

    if ((newp = realloc(vec->base, sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    vec->base = newp;

    return 0;
}

static void inbuf_dispose(struct st_ptls_iovec_t *vec)
{
    if (vec->base != NULL) {
        free(vec->base);
        vec->base = NULL;
        vec->len = 0;
    }
}

static void outbuf_init(struct st_ptls_outbuf_t *buf, uint8_t *output, size_t *outlen)
{
    buf->base = output;
    buf->capacity = *outlen;
    buf->off = outlen;
    *outlen = 0;

    if (buf->capacity == 0)
        buf->base = NULL;
}

#define outbuf_push(buf, ...) outbuf_pushv((buf), (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

static void outbuf_pushv(struct st_ptls_outbuf_t *buf, const uint8_t *src, size_t len)
{
    if (*buf->off + len <= buf->capacity)
        memcpy(buf->base + *buf->off, src, len);
    *buf->off += len;
}

static void outbuf_pushu16(struct st_ptls_outbuf_t *buf, uint16_t v)
{
    outbuf_push(buf, (uint8_t)(v >> 8), (uint8_t)v);
}

static void outbuf_do_encrypt_record(struct st_ptls_outbuf_t *buf, size_t rec_start, ptls_aead_context_t *aead)
{
    uint8_t encrypted[PTLS_MAX_RECORD_LENGTH + 256];
    size_t enclen;
    size_t bodylen = *buf->off - rec_start - 5;

    assert(bodylen <= PTLS_MAX_RECORD_LENGTH);

    if (*buf->off < buf->capacity) {
        buf->base[*buf->off] = buf->base[rec_start]; /* copy content_type to last +1!!! */
        enclen = aead->transform(aead, encrypted, buf->base + rec_start + 5, bodylen + 1);
    } else {
        enclen = aead->transform(aead, encrypted, NULL, bodylen + 1);
    }

    *buf->off = rec_start;
    outbuf_pushv(buf, encrypted, enclen);
}

#define outbuf_push_block(buf, _capacity, block)                                                                                   \
    do {                                                                                                                           \
        size_t capacity = (_capacity);                                                                                             \
        outbuf_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity);                                                                \
        size_t body_start = *(buf)->off;                                                                                           \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        if (body_start <= (buf)->capacity) {                                                                                       \
            size_t body_size = *(buf)->off - body_start;                                                                           \
            for (; capacity != 0; --capacity) {                                                                                    \
                (buf)->base[body_start - capacity] = (uint8_t)(body_size >> (8 * (capacity - 1)));                                 \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

#define outbuf_push_record(buf, type, block)                                                                                       \
    do {                                                                                                                           \
        outbuf_push((buf), (type), PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR);                                          \
        outbuf_push_block((buf), 2, block);                                                                                        \
    } while (0)

#define outbuf_encrypt(buf, enc, block)                                                                                            \
    do {                                                                                                                           \
        size_t rec_start = *(buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        outbuf_do_encrypt_record((buf), rec_start, (enc));                                                                         \
    } while (0);

#define outbuf_push_handshake(buf, type, block)                                                                                    \
    outbuf_push_record((buf), PTLS_CONTENT_TYPE_HANDSHAKE, {                                                                       \
        outbuf_push((buf), (type));                                                                                                \
        outbuf_push_block((buf), 3, block);                                                                                        \
    })

#define outbuf_push_extension(buf, type, block)                                                                                    \
    do {                                                                                                                           \
        outbuf_pushu16((buf), (type));                                                                                             \
        outbuf_push_block((buf), 2, block);                                                                                        \
    } while (0);

static int outbuf_push_certificate(struct st_ptls_outbuf_t *buf, X509 *cert)
{
    outbuf_push_block(buf, 3, {
        int len = i2d_X509(cert, NULL);
        if (len < 0)
            return PTLS_ERROR_LIBRARY;
        if (*buf->off + len <= buf->capacity) {
            unsigned char *p = buf->base + *buf->off;
            if (i2d_X509(cert, &p) != len)
                return PTLS_ERROR_LIBRARY;
        }
        *buf->off += len;
    });
    return 0;
}

static const uint8_t *parse_uint16(uint16_t *value, const uint8_t *src, const uint8_t *end)
{
    if (end - src < 2)
        return NULL;
    *value = readu16(src);
    return src + 2;
}

#define select_from_u16array(selected, src, end, maxlen, ...)                                                                      \
    _select_from_u16array((selected), (src), (end), (maxlen), (uint16_t[]){__VA_ARGS__},                                           \
                          sizeof((uint16_t[]){__VA_ARGS__}) / sizeof(uint16_t))

static int _select_from_u16array(uint16_t *selected, const uint8_t *src, const uint8_t *end, size_t maxlen,
                                 const uint16_t *candidates, size_t num_candidates)
{
    if (*selected != 0)
        return PTLS_ALERT_DECODE_ERROR;
    if (src == end || end - src > maxlen || (end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t v = readu16(src);
        size_t i;
        for (i = 0; i != num_candidates; ++i) {
            if (candidates[i] == v) {
                *selected = v;
                return 0;
            }
        }
    }

    return PTLS_ALERT_HANDSHAKE_FAILURE;
}

static int decode_server_name(struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    if (src == end)
        return PTLS_ALERT_DECODE_ERROR;

    while (src != end) {
        uint8_t type = *src++;
        uint16_t len;
        if ((src = parse_uint16(&len, src, end)) == NULL || end - src > len)
            return PTLS_ALERT_DECODE_ERROR;
        if (type == 0) {
            if (ch->server_name.base != NULL)
                return PTLS_ALERT_DECODE_ERROR;
            ch->server_name.base = (uint8_t *)src;
            ch->server_name.len = len;
        }
        src += len;
    }

    return 0;
}

static int decode_client_hello_key_share(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    uint16_t shareslen;

    if ((src = parse_uint16(&shareslen, src, end)) == NULL || end - src != shareslen)
        return PTLS_ALERT_DECODE_ERROR;

    while (shareslen != 0) {
        uint16_t group, keyexlen;
        if ((src = parse_uint16(&group, src, end)) == NULL)
            return PTLS_ALERT_DECODE_ERROR;
        if ((src = parse_uint16(&keyexlen, src, end)) == NULL || end - src < keyexlen)
            return PTLS_ALERT_DECODE_ERROR;
        if (ch->key_share.group == 0) {
            switch (group) {
            case PTLS_GROUP_SECP256R1:
                ch->key_share.group = PTLS_GROUP_SECP256R1;
                break;
            default:
                break;
            }
            if (ch->key_share.group != 0) {
                ch->key_share.peer.base = (uint8_t *)src;
                ch->key_share.peer.len = keyexlen;
            }
        }
        src += keyexlen;
    }

    return 0;
}

static int decode_client_hello_extensions(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    uint16_t selected_version = 0;
    int ret, seen_key_share = 0, seen_cookie = 0;

    while (src != end) {
        /* obtain type and datalen, advance src to the start of the next extension */
        uint16_t type, datalen;
        if ((src = parse_uint16(&type, src, end)) == NULL || (src = parse_uint16(&datalen, src, end)) == NULL ||
            datalen > end - src)
            return PTLS_ALERT_DECODE_ERROR;
        src += datalen;

        /* handle the extension */
        switch (type) {
        case PTLS_EXTENSION_TYPE_SERVER_NAME:
            if ((ret = decode_server_name(ch, src - datalen, src)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS:
            if ((ret = select_from_u16array(&ch->negotiated_group, src - datalen, src, 65534, PTLS_GROUP_SECP256R1)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            if ((ret = select_from_u16array(&ch->signature_algorithm, src - datalen, src, 65534, PTLS_SIGNATURE_RSA_PKCS1_SHA256,
                                            PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PSS_SHA256)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_KEY_SHARE:
            if (seen_key_share)
                return PTLS_ALERT_DECODE_ERROR;
            seen_key_share = 1;
            if ((ret = decode_client_hello_key_share(tls, ch, src - datalen, src)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS:
            if ((ret = select_from_u16array(&selected_version, src - datalen, src, 254, PTLS_PROTOCOL_VERSION_DRAFT16)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_COOKIE:
            if (seen_cookie)
                return PTLS_ALERT_DECODE_ERROR;
            seen_cookie = 1;
            break;
        default:
            /* TODO check collision of unknown extensions */
            break;
        }
    }

    if (ch->negotiated_group == 0 || ch->signature_algorithm == 0 || selected_version == 0 || !seen_key_share || !seen_cookie)
        return PTLS_ALERT_MISSING_EXTENSION;

    return 0;
}

static int decode_client_hello(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    int ret;

    *ch = (struct st_ptls_client_hello_t){};

    /* check protocol version */
    uint16_t protver;
    if ((src = parse_uint16(&protver, src, end)) == NULL || protver != PTLS_PROTOCOL_VERSION_DRAFT16)
        return PTLS_ALERT_DECODE_ERROR;

    /* decode random */
    if (end - src < sizeof(ch->random))
        return PTLS_ALERT_DECODE_ERROR;
    memcpy(ch->random, src, sizeof(ch->random));
    src += sizeof(ch->random);

    /* skip legacy_session_id */
    if (src == end)
        return PTLS_ALERT_DECODE_ERROR;
    uint8_t sesslen = *src++;
    if (sesslen > 32 || end - src < sesslen)
        return PTLS_ALERT_DECODE_ERROR;
    src += sesslen;

    /* decode and select from ciphersuites */
    uint16_t cslen;
    if ((src = parse_uint16(&cslen, src, end)) == NULL || end - src < cslen)
        return PTLS_ALERT_DECODE_ERROR;
    src += cslen;
    if ((ret = select_from_u16array(&ch->cipher_suite, src - cslen, src, 65534, PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
                                    PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) != 0)
        return ret;

    /* decode legacy_compression_methods */
    if (end - src < 2)
        return PTLS_ALERT_DECODE_ERROR;
    if (*src++ != 1)
        return PTLS_ALERT_DECODE_ERROR;
    if (*src++ != 0)
        return PTLS_ALERT_DECODE_ERROR;

    /* decode extensions, after checking that the length of extensions match the length left in CH */
    uint16_t extlen;
    if ((src = parse_uint16(&extlen, src, end)) == NULL || end - src != extlen)
        return PTLS_ALERT_DECODE_ERROR;
    return decode_client_hello_extensions(tls, ch, src, end);
}

static int ecdh_key_exchange(struct st_ptls_iovec_t *pubkey, struct st_ptls_iovec_t *secret, uint16_t group_id,
                             struct st_ptls_iovec_t *peerkey)
{
    EC_GROUP *group = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_POINT *peer_point = NULL;
    EC_KEY *privkey = NULL;
    int field_size, ret;

    assert(group_id == PTLS_GROUP_SECP256R1);

    if ((group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    field_size = EC_GROUP_get_degree(group);
    assert(field_size > 0);

    /* setup */
    pubkey->base = NULL;
    secret->base = NULL;
    if ((bn_ctx = BN_CTX_new()) == NULL || (peer_point = EC_POINT_new(group)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* decode peer key */
    if (EC_POINT_oct2point(group, peer_point, peerkey->base, peerkey->len, bn_ctx) == 0) {
        ret = PTLS_ALERT_DECODE_ERROR;
        goto Exit;
    }

    /* generate private key */
    if ((privkey = EC_KEY_new_by_curve_name(EC_GROUP_get_curve_name(group))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* encode public key */
    pubkey->len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(privkey), POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if ((pubkey->base = malloc(pubkey->len)) == NULL ||
        (pubkey->len = EC_POINT_point2oct(group, EC_KEY_get0_public_key(privkey), POINT_CONVERSION_UNCOMPRESSED, pubkey->base,
                                          pubkey->len, bn_ctx)) == 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* calc secret */
    secret->len = (field_size + 7) / 8;
    if ((secret->base = malloc(secret->len)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    /* ecdh! */
    if (ECDH_compute_key(secret->base, secret->len, peer_point, privkey, NULL) <= 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE; /* ??? */
        goto Exit;
    }

    ret = 0;

Exit:
    if (peer_point != NULL)
        EC_POINT_free(peer_point);
    if (privkey != NULL)
        EC_KEY_free(privkey);
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);
    if (group != NULL)
        EC_GROUP_free(group);
    if (ret != 0) {
        free(pubkey->base);
        free(secret->base);
    }
    return ret;
}

static const uint8_t *parse_record_header(struct st_ptls_record_t *rec, const uint8_t *src, const uint8_t *end)
{
    rec->type = src[0];
    rec->version = readu16(src + 1);
    rec->length = readu16(src + 3);

    if (rec->length >= PTLS_MAX_RECORD_LENGTH)
        return NULL;

    return src + 5;
}

static const uint8_t *parse_record(ptls_t *tls, struct st_ptls_record_t *rec, int *err, const uint8_t *src, const uint8_t *end)
{
    if (tls->recbuf.base == NULL && end - src >= 5) {
        /* fast path */
        const uint8_t *p = parse_record_header(rec, src, end);
        if (p != NULL && end - p <= rec->length) {
            rec->fragment = p;
            return p + rec->length;
        }
    }
    /* slow path follows */

    *rec = (struct st_ptls_record_t){0};
    if (tls->recbuf.base == NULL)
        if ((*err = inbuf_prepare(&tls->recbuf, 5 + PTLS_MAX_RECORD_LENGTH)) != 0)
            return NULL;

    /* fill and parse the header */
    while (tls->recbuf.len < 5) {
        if (src == end)
            return src;
        tls->recbuf.base[tls->recbuf.len++] = *src++;
    }
    if (parse_record_header(rec, src, end) == NULL) {
        *err = PTLS_ALERT_DECODE_ERROR;
        return NULL;
    }

    /* fill the fragment */
    size_t addlen = rec->length + 5 - tls->recbuf.len;
    if (addlen != 0) {
        if (addlen > end - src)
            addlen = end - src;
        memcpy(tls->recbuf.base + tls->recbuf.len, src, addlen);
    }
    src += addlen;
    tls->recbuf.len += addlen;

    /* set rec->fragment if a complete record has been parsed */
    if (tls->recbuf.len == rec->length + 5) {
        rec->fragment = tls->recbuf.base + 5;
    }

    return src;
}

ptls_t *ptls_new(ptls_context_t *ctx)
{
    ptls_t *tls = malloc(sizeof(*tls));
    if (tls != NULL)
        *tls = (ptls_t){PTLS_STATE_WAIT_CLIENT_HELLO, ctx};
    return tls;
}

void ptls_free(ptls_t *tls)
{
    inbuf_dispose(&tls->recbuf);
    inbuf_dispose(&tls->handshakebuf);
    free(tls);
}

static int extract_handshake_message(uint8_t *type, struct st_ptls_iovec_t *body, const uint8_t *src, size_t len)
{
    if (len < 4)
        return PTLS_ERROR_INCOMPLETE_HANDSHAKE;

    body->len = readu24(src + 1);

    if (body->len > len - 4) {
        return PTLS_ERROR_INCOMPLETE_HANDSHAKE;
    } else if (body->len < len - 4) {
        return PTLS_ALERT_DECODE_ERROR;
    }

    body->base = (uint8_t *)src + 4;
    return 0;
}

int ptls_handshake(ptls_t *tls, const void *input, size_t *inlen, void *output, size_t *outlen)
{
    const uint8_t *src = input;
    struct st_ptls_outbuf_t outbuf;
    struct st_ptls_record_t rec;
    uint8_t hstype;
    struct st_ptls_iovec_t hsbody;
    int ret;

    outbuf_init(&outbuf, output, outlen);

    /* extract the first record */
    if ((src = parse_record(tls, &rec, &ret, src, src + *inlen)) == NULL)
        return ret;
    *inlen = src - (const uint8_t *)input;
    if (rec.fragment == NULL)
        return PTLS_ERROR_INCOMPLETE_HANDSHAKE;

    /* validate as handshake message (and retain if partial) */
    if (rec.type != PTLS_CONTENT_TYPE_HANDSHAKE)
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    if (tls->handshakebuf.base == NULL && extract_handshake_message(&hstype, &hsbody, rec.fragment, rec.length) == 0) {
        /* first path; successfully extracted the handshake message from a single record */
    } else {
        /* handshake message split into multiple records, concat them into a buffer and handle when complete */
        /* TODO introduce ceiling for max size */
        if ((ret = inbuf_prepare(&tls->handshakebuf, tls->handshakebuf.len + rec.length)) != 0)
            return ret;
        memcpy(tls->handshakebuf.base + tls->handshakebuf.len, rec.fragment, rec.length);
        tls->handshakebuf.len += rec.length;
        if ((ret = extract_handshake_message(&hstype, &hsbody, tls->handshakebuf.base, tls->handshakebuf.len)) != 0)
            return ret;
    }

    switch (tls->state) {
    case PTLS_STATE_WAIT_CLIENT_HELLO: {
        struct st_ptls_client_hello_t ch;
        struct st_ptls_iovec_t pubkey, secret;
        X509 *cert;
        STACK_OF(X509) * extra_certs;

        /* decode ClientHello */
        if (hstype != PTLS_HANDSHAKE_TYPE_CLIENT_HELLO)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = decode_client_hello(tls, &ch, rec.fragment, rec.fragment + rec.length)) != 0)
            return ret;

        /* send HelloRetryRequest or abort the handshake if failed to obtain the key */
        if (ch.key_share.group == 0) {
            if (ch.negotiated_group != 0) {
                outbuf_push_handshake(&outbuf, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, {
                    outbuf_pushu16(&outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
                    outbuf_push_block(&outbuf, 2, {
                        outbuf_push_extension(&outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,
                                              { outbuf_pushu16(&outbuf, ch.negotiated_group); });
                    });
                });
                return PTLS_ERROR_INCOMPLETE_HANDSHAKE;
            } else {
                return PTLS_ALERT_HANDSHAKE_FAILURE;
            }
        }

        /* run post-hello callback to determine certificate, etc. */
        if ((ret = tls->ctx->callbacks.server_name(tls, &cert, &extra_certs)) != 0)
            return ret;

        /* run key-exchange, to obtain pubkey and secret */
        if ((ret = ecdh_key_exchange(&pubkey, &secret, ch.key_share.group, &ch.key_share.peer)) != 0)
            return ret;

        uint8_t server_random[32];
        RAND_bytes(server_random, sizeof(server_random));

        /* send ServerHello */
        outbuf_push_handshake(&outbuf, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {
            outbuf_pushu16(&outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
            outbuf_pushv(&outbuf, server_random, sizeof(server_random));
            outbuf_pushu16(&outbuf, ch.cipher_suite);
            outbuf_push_block(&outbuf, 2, {
                outbuf_push_extension(&outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                    outbuf_pushu16(&outbuf, ch.key_share.group);
                    outbuf_push_block(&outbuf, 2, { outbuf_pushv(&outbuf, pubkey.base, pubkey.len); });
                });
                outbuf_push_extension(&outbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {});
            });
        });

        ptls_aead_context_t *aead = NULL;

        outbuf_encrypt(&outbuf, aead, { outbuf_push_handshake(&outbuf, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {}); });
        outbuf_encrypt(&outbuf, aead, {
            outbuf_push_handshake(&outbuf, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
                outbuf_push(&outbuf, 0);
                outbuf_push_block(&outbuf, 3, {
                    if ((ret = outbuf_push_certificate(&outbuf, cert)) != 0)
                        return ret;
                    int i;
                    for (i = 0; i < sk_X509_num(extra_certs); ++i)
                        if ((ret = outbuf_push_certificate(&outbuf, sk_X509_value(extra_certs, i))) != 0)
                            return ret;
                });
            });
        });
    } break;
    default:
        assert(!"unexpected state");
        break;
    }

    return 0;
}
