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
#include "picotls.h"

#define PICOTLS_MAX_RECORD_LENGTH 16384

#define PICOTLS_CONTENT_TYPE_ALERT 21
#define PICOTLS_CONTENT_TYPE_HANDSHAKE 22
#define PICOTLS_CONTENT_TYPE_APPDATA 23

/* cipher-suites */
#define PICOTLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define PICOTLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define PICOTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* negotiated_groups */
#define PICOTLS_GROUP_SECP256R1 23
#define PICOTLS_GROUP_X25519 29

/* signature algorithms */
#define PICOTLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define PICOTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define PICOTLS_SIGNATURE_RSA_PSS_SHA256 0x0804

#define PICOTLS_PROTOCOL_VERSION_DRAFT16 0x7f16

struct st_picotls_iovec_t {
    uint8_t *base;
    size_t len;
};

struct st_picotls_t {
    enum {
        PICOTLS_STATE_WAIT_CLIENT_HELLO,
        PICOTLS_STATE_WAIT_FINISHED,
        PICOTLS_STATE_APPDATA
    } state;
    struct st_picotls_iovec_t recbuf;
};

struct st_picotls_record_t {
    uint8_t type;
    uint16_t version;
    uint16_t length;
    const uint8_t *fragment;
};

struct st_picotls_client_hello_t {
    uint8_t random[32];
    uint16_t cipher_suite;
    uint16_t negotiated_group;
    uint16_t signature_algorithm;
    uint32_t *key_share;
};

static uint16_t to_uint16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

static const uint8_t *parse_uint16(const uint8_t *src, const uint8_t *end, uint16_t *value)
{
    if (end - src < 2)
        return NULL;
    *value = to_uint16(src);
    return src + 2;
}

#define select_from_u16array(selected, src, end, maxlen, ...) _select_from_u16array(selected, src, end, maxlen, (uint16_t[]){__VA_ARGS__}, sizeof((uint16_t[]){__VA_ARGS__}) / sizeof(uint16_t))
static int _select_from_u16array(uint16_t *selected, const uint8_t *src, const uint8_t *end, size_t maxlen, const uint16_t *candidates, size_t num_candidates)
{
    if (*selected != 0)
        return PICOTLS_ALERT_DECODE_ERROR;
    if (src == end || end - src > maxlen || (end - src) % 2 != 0)
        return PICOTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t v = to_uint16(src);
        size_t i;
        for (i = 0; i != num_candidates; ++i) {
            if (candidates[i] == v) {
                *selected = v;
                return 0;
            }
        }
    }

    return PICOTLS_ALERT_HANDSHAKE_FAILURE;
}

static int decode_client_hello_extensions(picotls_t *tls, struct st_picotls_client_hello_t *ch, const uint8_t *src,
                                          const uint8_t *end)
{
    uint16_t selected_version = 0;
    int ret, seen_cookie = 0;

    while (src != end) {
        /* obtain type and datalen, advance src to the start of the next extension */
        uint16_t type, datalen;
        if ((src = parse_uint16(src, end, &type)) == NULL || (src = parse_uint16(src, end, &datalen)) == NULL ||
             datalen > end - src)
            return PICOTLS_ALERT_DECODE_ERROR;
        src += datalen;

        /* handle the extension */
        switch (type) {
        case 10: /* supported_groups */
            if ((ret = select_from_u16array(&ch->negotiated_group, src - datalen, src, 65534, PICOTLS_GROUP_SECP256R1,
                                            PICOTLS_GROUP_X25519)) != 0)
                return ret;
            break;
        case 13: /* signature_algorithms */
            if ((ret = select_from_u16array(&ch->signature_algorithm, src - datalen, src, 65534,
                                            PICOTLS_SIGNATURE_RSA_PKCS1_SHA256, PICOTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                                            PICOTLS_SIGNATURE_RSA_PSS_SHA256)) != 0)
                return ret;
            break;
        case 40: /* key_share */
            if (decode_key_share(&ch->key_share, src - datalen, src) != src)
                return PICOTLS_ALERT_DECODE_ERROR;
            break;
        case 43: /* supported_versions */
            if ((ret = select_from_u16array(&selected_version, src - datalen, src, 254, PICOTLS_PROTOCOL_VERSION_DRAFT16)) != 0)
                return ret;
            break;
        case 44: /* cookie */
            if (seen_cookie)
                return PICOTLS_ALERT_DECODE_ERROR;
            seen_cookie = 1;
            break;
        default:
            /* TODO check collision of unknown extensions */
            break;
        }
    }

    if (ch->negotiated_group == 0 || ch->signature_algorithm == 0 || selected_version == 0 || !seen_cookie)
        return PICOTLS_ALERT_MISSING_EXTENSION;

    return 0;
}

static int decode_client_hello(picotls_t *tls, const uint8_t *src, const uint8_t *end)
{
    struct st_picotls_client_hello_t ch = {};
    int ret;

    /* decode random */
    if (end - src < sizeof(ch.random))
        return PICOTLS_ALERT_DECODE_ERROR;
    memcpy(ch.random, src, sizeof(ch.random));
    src += sizeof(ch.random);

    /* skip legacy_session_id */
    if (src == end)
        return PICOTLS_ALERT_DECODE_ERROR;
    uint8_t sesslen = *src++;
    if (sesslen > 32 || end - src < sesslen)
        return PICOTLS_ALERT_DECODE_ERROR;
    src += sesslen;

    /* decode and select from ciphersuites */
    uint16_t cslen;
    if ((src = parse_uint16(src, end, &cslen)) == NULL || end - src < cslen)
        return PICOTLS_ALERT_DECODE_ERROR;
    src += cslen;
    if ((ret = select_from_u16array(&ch.cipher_suite, src - cslen, src, 65534, PICOTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
                                    PICOTLS_CIPHER_SUITE_AES_256_GCM_SHA384, PICOTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256)) != 0)
        return ret;

    /* decode legacy_compression_methods */
    if (end - src < 2)
        return PICOTLS_ALERT_DECODE_ERROR;
    if (*src++ != 1)
        return PICOTLS_ALERT_DECODE_ERROR;
    if (*src++ != 0)
        return PICOTLS_ALERT_DECODE_ERROR;

    /* decode extensions, after checking that the length of extensions match the length left in CH */
    uint16_t extlen;
    if ((src = parse_uint16(src, end, &extlen)) == NULL || end - src != extlen)
        return PICOTLS_ALERT_DECODE_ERROR;
    return decode_client_hello_extensions(tls, &ch, src, end);
}

static void prepare_recbuf(picotls_t *tls)
{
    if (tls->recbuf.base == NULL) {
        tls->recbuf.base = malloc(5 + PICOTLS_MAX_RECORD_LENGTH);
        tls->recbuf.len = 0;
    }
}

static void dispose_recbuf(picotls_t *tls)
{
    if (tls->recbuf.base != NULL) {
        free(tls->recbuf.base);
        tls->recbuf.base = NULL;
        tls->recbuf.len = 0;
    }
}

static const uint8_t *parse_record_header(picotls_t *tls, const uint8_t *src, const uint8_t *end, struct st_picotls_record_t *rec)
{
    if (end - src < 5)
        return NULL;

    rec->type = src[0];
    rec->version = to_uint16(src + 1);
    rec->length = to_uint16(src + 3);

    if (rec->length >= PICOTLS_MAX_RECORD_LENGTH)
        return NULL;

    return src + 5;
}

static const uint8_t *parse_record(picotls_t *tls, const uint8_t *src, const uint8_t *end, struct st_picotls_record_t *rec)
{
    if (tls->recbuf.base == NULL) {
        /* fast path */
        const uint8_t *p = parse_record_header(tls, src, end, rec);
        if (p != NULL && end - p <= rec->length) {
            rec->fragment = p;
            return p + rec->length;
        }
    }
    /* slow path follows */

    *rec = (struct st_picotls_record_t){0};
    prepare_recbuf(tls);

    /* fill and parse the header */
    while (tls->recbuf.len < 5) {
        if (src == end)
            return src;
        tls->recbuf.base[tls->recbuf.len++] = *src++;
    }
    if (parse_record_header(tls, src, end, rec) == NULL)
        return NULL;

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

picotls_t *picotls_new(void)
{
    picotls_t *tls = malloc(sizeof(*tls));
    if (tls != NULL)
        *tls = (picotls_t){PICOTLS_STATE_WAIT_CLIENT_HELLO};
    return tls;
}

void picotls_free(picotls_t *tls)
{
    free(tls);
}

int picotls_handshake(picotls_t *tls, const void *input, size_t *inlen, void *output, size_t *outlen)
{
    const uint8_t *src = input;
    uint8_t *dst = output, *dst_end = dst + *outlen;
    int ret;
    struct st_picotls_record_t rec;

    assert(tls->state == PICOTLS_STATE_WAIT_CLIENT_HELLO);
    *outlen = 0;

    if ((src = parse_record(tls, src, src + *inlen, &rec)) == NULL)
        return PICOTLS_ALERT_DECODE_ERROR;
    *inlen = src - (const uint8_t *)input;

    if (rec.fragment == NULL)
        return PICOTLS_ERROR_HANDSHAKE_INCOMPLETE;

    if (!(rec.type == PICOTLS_CONTENT_TYPE_HANDSHAKE && rec.version == 0x0303))
        return PICOTLS_ALERT_HANDSHAKE_FAILURE;

    if ((ret = decode_client_hello(tls, rec.fragment, rec.fragment + rec.length)) != 0)
        return ret;

    return 0;
}
