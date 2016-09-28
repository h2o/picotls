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
#include <stdlib.h>
#include <string.h>
#include "picotls.h"

#define PTLS_MAX_RECORD_LENGTH 16384

#define PTLS_RECORD_VERSION_MAJOR 3
#define PTLS_RECORD_VERSION_MINOR 1

#define PTLS_HELLO_RANDOM_SIZE 32

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
#define PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY 15
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
    ptls_iovec_t recbuf;
    /**
     * buffer for retaining partial handshake message
     */
    ptls_iovec_t handshakebuf;
    /**
     * key schedule
     */
    struct st_ptls_key_schedule_t *key_schedule;
};

struct st_ptls_record_t {
    uint8_t type;
    uint16_t version;
    uint16_t length;
    const uint8_t *fragment;
};

struct st_ptls_client_hello_t {
    uint8_t random[32];
    ptls_cipher_suite_t *cipher_suite;
    ptls_iovec_t server_name;
    ptls_key_exchange_algorithm_t *negotiated_group;
    struct {
        uint16_t list[16]; /* expand? */
        size_t count;
    } signature_algorithms;
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer;
    } key_share;
};

struct st_ptls_key_schedule_t {
    ptls_hash_algorithm_t *algo;
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    uint8_t hashed_resumption_context[PTLS_MAX_DIGEST_SIZE];
    ptls_hash_context_t *msghash;
};

static uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {};

static uint16_t readu16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

static uint32_t readu24(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

static int inbuf_prepare(ptls_iovec_t *vec, size_t sz)
{
    uint8_t *newp;

    if ((newp = realloc(vec->base, sz)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    vec->base = newp;

    return 0;
}

static void inbuf_dispose(ptls_iovec_t *vec)
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

static void outbuf_pushv(struct st_ptls_outbuf_t *buf, const void *src, size_t len)
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

#define outbuf_push_handshake(buf, key_sched, type, block)                                                                         \
    outbuf_push_record((buf), PTLS_CONTENT_TYPE_HANDSHAKE, {                                                                       \
        outbuf_push((buf), (type));                                                                                                \
        outbuf_push_block((buf), 3, {                                                                                              \
            size_t body_start = *(buf)->off;                                                                                       \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
            if ((key_sched) != NULL && *(buf)->off <= (buf)->capacity)                                                             \
                update_key_schedule((key_sched), (buf)->base + body_start, *(buf)->off - body_start);                              \
        } block);                                                                                                                  \
    })

#define outbuf_push_extension(buf, type, block)                                                                                    \
    do {                                                                                                                           \
        outbuf_pushu16((buf), (type));                                                                                             \
        outbuf_push_block((buf), 2, block);                                                                                        \
    } while (0);

static int hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label1,
                             const char *label2, ptls_iovec_t hash_value)
{
    uint8_t hkdf_label[514];
    size_t hkdf_label_off = 0;
    struct st_ptls_outbuf_t outbuf;

    outbuf_init(&outbuf, hkdf_label, &hkdf_label_off);

    outbuf_pushu16(&outbuf, outlen);
    outbuf_push_block(&outbuf, 1, {
        const char *prefix = "TLS 1.3, ";
        outbuf_pushv(&outbuf, prefix, strlen(prefix));
        outbuf_pushv(&outbuf, label1, strlen(label1));
        outbuf_pushv(&outbuf, label2, strlen(label2));
    });
    outbuf_push_block(&outbuf, 1, { outbuf_pushv(&outbuf, hash_value.base, hash_value.len); });

    assert(hkdf_label_off <= sizeof(hkdf_label));

    int ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label, hkdf_label_off));

    ptls_clear_memory(hkdf_label, hkdf_label_off);
    return ret;
}

static struct st_ptls_key_schedule_t *new_key_schedule(ptls_hash_algorithm_t *algo, ptls_iovec_t resumption_context)
{
    struct st_ptls_key_schedule_t *sched = NULL;
    ptls_hash_context_t *hash = NULL;

    if ((sched = malloc(sizeof(*sched))) != NULL || (hash = algo->create()) == NULL) {
        free(sched);
        if (hash != NULL)
            hash->final(hash, NULL, PTLS_HASH_FINAL_MODE_FREE);
        return NULL;
    }

    *sched = (struct st_ptls_key_schedule_t){algo};

    /* calc resumption context */
    if (resumption_context.base == NULL)
        resumption_context = ptls_iovec_init(zeroes_of_max_digest_size, algo->digest_size);
    hash->update(hash, resumption_context.base, resumption_context.len);
    hash->final(hash, sched->hashed_resumption_context, PTLS_HASH_FINAL_MODE_RESET);

    /* reuse the hash context (reset above) */
    sched->msghash = hash;

    return sched;

NoMemory:
    if (sched->msghash != NULL)
        sched->msghash->final(sched->msghash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
    return NULL;
}

static void free_key_schedule(struct st_ptls_key_schedule_t *sched)
{
    sched->msghash->final(sched->msghash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
}

static int roll_key_schedule(struct st_ptls_key_schedule_t *sched, ptls_iovec_t addition)
{
    if (addition.base == NULL)
        addition = ptls_iovec_init(zeroes_of_max_digest_size, sched->algo->digest_size);

    ++sched->generation;
    return ptls_hkdf_extract(sched->algo, sched->secret, ptls_iovec_init(sched->secret, sched->algo->digest_size), addition);
}

static void update_key_schedule(struct st_ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen)
{
    sched->msghash->update(sched->msghash, msg, msglen);
}

static int derive_secret(struct st_ptls_key_schedule_t *sched, void *secret, const char *label)
{
    uint8_t hash_value[PTLS_MAX_DIGEST_SIZE * 2];

    sched->msghash->final(sched->msghash, hash_value, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    memcpy(hash_value + sched->algo->digest_size, sched->hashed_resumption_context, sched->algo->digest_size);

    int ret =
        hkdf_expand_label(sched->algo, secret, sched->algo->digest_size, ptls_iovec_init(sched->secret, sched->algo->digest_size),
                          label, "", ptls_iovec_init(hash_value, sched->algo->digest_size * 2));

    ptls_clear_memory(hash_value, sched->algo->digest_size * 2);
    return ret;
}

static int get_traffic_key(ptls_hash_algorithm_t *algo, void *key, size_t key_size, const char *label, int is_iv,
                           const void *secret)
{
    return hkdf_expand_label(algo, key, key_size, ptls_iovec_init(secret, algo->digest_size), label, is_iv ? "iv" : "key",
                             ptls_iovec_init(NULL, 0));
}

static ptls_aead_context_t *create_encrypter(ptls_cipher_suite_t *cs, const char *label, const void *traffic_secret)
{
    uint8_t traffic_key[PTLS_MAX_SECRET_SIZE];

    if (get_traffic_key(cs->hash, traffic_key, cs->aead->key_size, "handshake key expansion", 0, traffic_secret) != 0)
        return NULL;

    ptls_aead_context_t *enc = cs->aead->create(traffic_key);

    ptls_clear_memory(traffic_key, sizeof(traffic_key));
    return enc;
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

static int select_cipher_suite(ptls_crypto_t *crypto, ptls_cipher_suite_t **algo, const uint8_t *src, const uint8_t *end)
{
    if ((end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = readu16(src);
        ptls_cipher_suite_t *a = crypto->cipher_suites;
        for (; a->id != UINT16_MAX; ++a) {
            if (a->id == id) {
                *algo = a;
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

static int select_negotiated_group(ptls_crypto_t *crypto, ptls_key_exchange_algorithm_t **algo, const uint8_t *src,
                                   const uint8_t *end)
{
    if ((end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = readu16(src);
        ptls_key_exchange_algorithm_t *a = crypto->key_exchanges;
        for (; a->id != UINT16_MAX; ++a) {
            if (a->id == id) {
                *algo = a;
                return 0;
            }
        }
    }

    return PTLS_ALERT_HANDSHAKE_FAILURE;
}

static int record_signature_algorithms(struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    if ((end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = readu16(src);
        if (ch->signature_algorithms.count < sizeof(ch->signature_algorithms.list) / sizeof(ch->signature_algorithms.list[0]))
            ch->signature_algorithms.list[ch->signature_algorithms.count++] = id;
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
        if (ch->key_share.algorithm == NULL) {
            ptls_key_exchange_algorithm_t *a = tls->ctx->crypto->key_exchanges;
            for (; a->id != UINT16_MAX; ++a) {
                if (a->id == group) {
                    ch->key_share.algorithm = a;
                    ch->key_share.peer.base = (uint8_t *)src;
                    ch->key_share.peer.len = keyexlen;
                    break;
                }
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
            if ((ret = select_negotiated_group(tls->ctx->crypto, &ch->negotiated_group, src - datalen, src)) != 0)
                return ret;
            break;
        case PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS:
            if ((ret = record_signature_algorithms(ch, src - datalen, src)) != 0)
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

    if (ch->negotiated_group == NULL || ch->signature_algorithms.count == 0 || selected_version == 0 || !seen_key_share ||
        !seen_cookie)
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
    if ((ret = select_cipher_suite(tls->ctx->crypto, &ch->cipher_suite, src - cslen, src)) != 0)
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

static int handle_client_hello(ptls_t *tls, struct st_ptls_outbuf_t *outbuf, const uint8_t *src, size_t src_len)
{
    struct st_ptls_client_hello_t ch;
    ptls_iovec_t *certs;
    size_t num_certs;
    uint16_t sign_algorithm;
    int (*signer)(void *, ptls_iovec_t *, ptls_iovec_t);
    void *signer_data;
    ptls_iovec_t pubkey = {}, ecdh_secret = {};
    uint8_t handshake_server_traffic_secret[PTLS_MAX_DIGEST_SIZE];
    ptls_aead_context_t *enc = NULL;
    int ret;

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls, &ch, src, src + src_len)) != 0)
        goto Exit;

    /* send HelloRetryRequest or abort the handshake if failed to obtain the key */
    if (ch.key_share.algorithm == NULL) {
        if (ch.negotiated_group != NULL) {
            outbuf_push_handshake(outbuf, NULL, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, {
                outbuf_pushu16(outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
                outbuf_push_block(outbuf, 2, {
                    outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,
                                          { outbuf_pushu16(outbuf, ch.negotiated_group->id); });
                });
            });
            ret = PTLS_ERROR_INCOMPLETE_HANDSHAKE;
            goto Exit;
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            goto Exit;
        }
    }

    /* run post-hello callback to determine certificate, etc. */
    if ((ret = tls->ctx->callbacks.client_hello(tls, &sign_algorithm, &signer, &signer_data, &certs, &num_certs, ch.server_name,
                                                ch.signature_algorithms.list, ch.signature_algorithms.count)) != 0)
        goto Exit;
    assert(sign_algorithm != 0);

    /* run key-exchange, to obtain pubkey and secret */
    if ((ret = ch.key_share.algorithm->key_exchange(&pubkey, &ecdh_secret, ch.key_share.peer)) != 0)
        goto Exit;

    /* create key schedule and feed the initial values supplied from the client */
    assert(tls->key_schedule == NULL);
    tls->key_schedule = new_key_schedule(ch.cipher_suite->hash, ptls_iovec_init(NULL, 0));
    roll_key_schedule(tls->key_schedule, ptls_iovec_init(NULL, 0));
    update_key_schedule(tls->key_schedule, src, src_len);

    /* send ServerHello */
    outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {
        outbuf_pushu16(outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
        if (*outbuf->off + PTLS_HELLO_RANDOM_SIZE <= outbuf->capacity)
            tls->ctx->crypto->random_bytes(outbuf->base + *outbuf->off, PTLS_HELLO_RANDOM_SIZE);
        *outbuf->off += PTLS_HELLO_RANDOM_SIZE;
        outbuf_pushu16(outbuf, ch.cipher_suite->id);
        outbuf_push_block(outbuf, 2, {
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                outbuf_pushu16(outbuf, ch.key_share.algorithm->id);
                outbuf_push_block(outbuf, 2, { outbuf_pushv(outbuf, pubkey.base, pubkey.len); });
            });
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {});
        });
    });

    /* create encryptor for encrypting the handshake */
    derive_secret(tls->key_schedule, handshake_server_traffic_secret, "server handshake traffic secret");
    if ((enc = create_encrypter(ch.cipher_suite, "handshake key expansion", handshake_server_traffic_secret)) == NULL)
        goto Exit;

    /* send EncryptedExtensions, Certificate */
    outbuf_encrypt(outbuf, enc,
                   { outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {}); });
    outbuf_encrypt(outbuf, enc, {
        outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
            outbuf_push(outbuf, 0);
            outbuf_push_block(outbuf, 3, {
                for (size_t i = 0; i != num_certs; ++i) {
                    outbuf_push_block(outbuf, 3, { outbuf_pushv(outbuf, certs[i].base, certs[i].len); });
                }
            });
        });
    });

#define CONTEXT_STRING "TLS 1.3, server CertificateVerify"
    /* build and send CertificateVerify */
    outbuf_encrypt(outbuf, enc, {
        outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
            uint8_t data[64 + sizeof(CONTEXT_STRING) + PTLS_MAX_DIGEST_SIZE * 2];
            size_t datalen = 0;
            ptls_iovec_t sign;

            /* build data to be signed */
            memset(data + datalen, 0x32, 32);
            datalen += 32;
            memcpy(data + datalen, CONTEXT_STRING, sizeof(CONTEXT_STRING));
            datalen += sizeof(CONTEXT_STRING);
            tls->key_schedule->msghash->final(tls->key_schedule->msghash, data + datalen, PTLS_HASH_FINAL_MODE_SNAPSHOT);
            datalen += tls->key_schedule->algo->digest_size;
            memcpy(data + datalen, tls->key_schedule->hashed_resumption_context, tls->key_schedule->algo->digest_size);
            datalen += tls->key_schedule->algo->digest_size;
            assert(datalen <= sizeof(data));

            /* sign */
            ret = signer(signer_data, &sign, ptls_iovec_init(data, datalen));
            ptls_clear_memory(data, datalen);
            if (ret != 0)
                goto Exit;

            /* emit */
            outbuf_pushu16(outbuf, sign_algorithm);
            outbuf_push_block(outbuf, 2, { outbuf_pushv(outbuf, sign.base, sign.len); });
            free(sign.base);
        });
    });
#undef CONTEXT_STRING

    assert(!"implement finished");
    ret = -1;

Exit:
    free(pubkey.base);
    free(ecdh_secret.base);
    ptls_clear_memory(handshake_server_traffic_secret, sizeof(handshake_server_traffic_secret));
    if (enc != NULL)
        enc->destroy(enc);
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
    if (tls->key_schedule != NULL)
        free_key_schedule(tls->key_schedule);
    free(tls);
}

static int extract_handshake_message(uint8_t *type, ptls_iovec_t *body, const uint8_t *src, size_t len)
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
    ptls_iovec_t hsbody;
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
    case PTLS_STATE_WAIT_CLIENT_HELLO:
        if (hstype != PTLS_HANDSHAKE_TYPE_CLIENT_HELLO)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = handle_client_hello(tls, &outbuf, hsbody.base, hsbody.len)) != 0)
            return ret;
        break;
    default:
        assert(!"unexpected state");
        break;
    }

    return 0;
}

struct st_picotls_hmac_context_t {
    ptls_hash_context_t super;
    ptls_hash_algorithm_t *algo;
    ptls_hash_context_t *hash;
    uint8_t key[1];
};

static void hmac_update(ptls_hash_context_t *_ctx, const void *src, size_t len)
{
    struct st_picotls_hmac_context_t *ctx = (struct st_picotls_hmac_context_t *)_ctx;
    ctx->hash->update(ctx->hash, src, len);
}

static void hmac_apply_key(struct st_picotls_hmac_context_t *ctx, uint8_t pad)
{
    size_t i;

    for (i = 0; i != ctx->algo->block_size; ++i)
        ctx->key[i] ^= pad;
    ctx->hash->update(ctx->hash, ctx->key, ctx->algo->block_size);
    for (i = 0; i != ctx->algo->block_size; ++i)
        ctx->key[i] ^= pad;
}

static void hmac_final(ptls_hash_context_t *_ctx, void *md, ptls_hash_final_mode_t mode)
{
    struct st_picotls_hmac_context_t *ctx = (struct st_picotls_hmac_context_t *)_ctx;

    assert(mode != PTLS_HASH_FINAL_MODE_SNAPSHOT || !"not supported");

    if (md != NULL) {
        ctx->hash->final(ctx->hash, md, 1);
        hmac_apply_key(ctx, 0x5c);
        ctx->hash->update(ctx->hash, md, ctx->algo->digest_size);
        ctx->hash->final(ctx->hash, md, mode);
    }

    switch (mode) {
    case PTLS_HASH_FINAL_MODE_FREE:
        ptls_clear_memory(ctx->key, ctx->algo->block_size);
        free(ctx);
        break;
    case PTLS_HASH_FINAL_MODE_RESET:
        hmac_apply_key(ctx, 0x36);
        break;
    default:
        assert(!"FIXME");
        break;
    }
}

ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size)
{
    struct st_picotls_hmac_context_t *ctx;

    if ((ctx = malloc(offsetof(struct st_picotls_hmac_context_t, key) + algo->block_size)) == NULL)
        return NULL;

    *ctx = (struct st_picotls_hmac_context_t){{hmac_update, hmac_final}, algo};
    if ((ctx->hash = algo->create()) == NULL) {
        free(ctx);
        return NULL;
    }
    memset(ctx->key, 0, algo->block_size);
    memcpy(ctx->key, key, key_size);

    hmac_apply_key(ctx, 0x36);

    return &ctx->super;
}

int ptls_hkdf_extract(ptls_hash_algorithm_t *algo, void *output, ptls_iovec_t salt, ptls_iovec_t ikm)
{
    ptls_hash_context_t *hash;

    if (salt.len == 0)
        salt = ptls_iovec_init(zeroes_of_max_digest_size, algo->digest_size);

    if ((hash = ptls_hmac_create(algo, salt.base, salt.len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    hash->update(hash, ikm.base, ikm.len);
    hash->final(hash, output, PTLS_HASH_FINAL_MODE_FREE);
    return 0;
}

int ptls_hkdf_expand(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t prk, ptls_iovec_t info)
{
    ptls_hash_context_t *hmac = NULL;
    size_t i;
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];

    for (i = 0; (i * algo->digest_size) < outlen; ++i) {
        if (hmac == NULL) {
            if ((hmac = ptls_hmac_create(algo, prk.base, prk.len)) == NULL)
                return PTLS_ERROR_NO_MEMORY;
        } else {
            hmac->update(hmac, digest, algo->digest_size);
        }
        hmac->update(hmac, info.base, info.len);
        uint8_t gen = i + 1;
        hmac->update(hmac, &gen, 1);
        hmac->final(hmac, digest, 1);

        size_t off_start = i * algo->digest_size, off_end = off_start + algo->digest_size;
        if (off_end > outlen)
            off_end = outlen;
        memcpy(output + off_start, digest, off_end - off_start);
    }

    if (hmac != NULL)
        hmac->final(hmac, NULL, PTLS_HASH_FINAL_MODE_FREE);

    ptls_clear_memory(digest, algo->digest_size);

    return 0;
}

static void clear_memory(void *p, size_t len)
{
    memset(p, 0, len);
}

void (*volatile ptls_clear_memory)(void *p, size_t len) = clear_memory;
