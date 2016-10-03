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
    int is_allocated;
};

struct st_ptls_t {
    /**
     * context
     */
    ptls_context_t *ctx;
    /**
     * the state
     */
    enum {
        PTLS_STATE_CLIENT_HANDSHAKE_START,
        PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO,
        PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
        PTLS_STATE_SERVER_EXPECT_FINISHED,
        PTLS_STATE_APPDATA
    } state;
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
    /**
     * misc.
     */
    struct {
        struct {
            char *server_name;
            ptls_key_exchange_context_t *key_exchange;
        } client;
    };
};

struct st_ptls_record_t {
    uint8_t type;
    uint16_t version;
    uint16_t length;
    const uint8_t *fragment;
};

struct st_ptls_client_hello_t {
    ptls_cipher_suite_t *cipher_suite;
    struct {
        const uint8_t *ids;
        size_t count;
    } compression_methods;
    ptls_iovec_t server_name;
    uint16_t selected_version;
    ptls_key_exchange_algorithm_t *negotiated_group;
    struct {
        uint16_t list[16]; /* expand? */
        size_t count;
    } signature_algorithms;
    struct {
        ptls_key_exchange_algorithm_t *algorithm;
        ptls_iovec_t peer;
    } key_share;
    ptls_iovec_t cookie;
};

struct st_ptls_server_hello_t {
    uint8_t random[PTLS_HELLO_RANDOM_SIZE];
    ptls_cipher_suite_t *cipher_suite;
};

struct st_ptls_key_schedule_t {
    ptls_hash_algorithm_t *algo;
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    uint8_t hashed_resumption_context[PTLS_MAX_DIGEST_SIZE];
    ptls_hash_context_t *msghash;
};

struct st_ptls_extension_decoder_t {
    uint16_t type;
    int (*cb)(ptls_t *tls, void *arg, const uint8_t *src, const uint8_t *end);
};

static uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {};
static ptls_key_exchange_algorithm_t key_exchange_no_match;

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

static void outbuf_init(struct st_ptls_outbuf_t *buf, uint8_t *output, size_t *outlen, size_t capacity)
{
    buf->base = output;
    buf->off = outlen;
    buf->capacity = capacity;
    buf->is_allocated = 0;
    *buf->off = 0;
}

static void outbuf__release_memory(struct st_ptls_outbuf_t *buf)
{
    if (buf->base == NULL)
        return;

    ptls_clear_memory(buf->base, *buf->off);
    if (buf->is_allocated)
        free(buf->base);
    buf->base = NULL;
}

static void outbuf_reserve(struct st_ptls_outbuf_t *buf, size_t delta)
{
    if (buf->base == NULL)
        return;

    if (buf->capacity < *buf->off + delta) {
        uint8_t *newp;
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < 1024)
            new_capacity = 1024;
        if ((newp = malloc(new_capacity)) == NULL) {
            outbuf__release_memory(buf);
            return;
        }
        memcpy(newp, buf->base, *buf->off);
        outbuf__release_memory(buf);
        buf->base = newp;
        buf->capacity = new_capacity;
        buf->is_allocated = 1;
    }
}

#define outbuf_push(buf, ...) outbuf_pushv((buf), (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

static void outbuf_pushv(struct st_ptls_outbuf_t *buf, const void *src, size_t len)
{
    outbuf_reserve(buf, len);
    if (buf->base != NULL)
        memcpy(buf->base + *buf->off, src, len);
    *buf->off += len;
}

static void outbuf_pushu16(struct st_ptls_outbuf_t *buf, uint16_t v)
{
    outbuf_push(buf, (uint8_t)(v >> 8), (uint8_t)v);
}

static void outbuf_do_encrypt_record(struct st_ptls_outbuf_t *buf, size_t rec_start, ptls_aead_context_t *aead)
{
    /* section 5.2: The length MUST NOT exceed 2^14 + 256. */
    uint8_t encrypted[PTLS_MAX_RECORD_LENGTH + 256];
    size_t enclen;
    const uint8_t *src;
    size_t bodylen = *buf->off - rec_start - 5;

    assert(bodylen <= PTLS_MAX_RECORD_LENGTH);

    if (buf->base != NULL) {
        buf->base[*buf->off] = buf->base[rec_start]; /* copy content_type to last +1!!! */
        src = buf->base + rec_start + 5;
    } else {
        /* encrypt garbage to obtain size */
        src = encrypted;
    }

    int ret = ptls_aead_transform(aead, encrypted, &enclen, src, bodylen + 1);
    assert(ret == 0);

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
        if ((buf)->base != NULL) {                                                                                                 \
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
            if ((key_sched) != NULL && (buf)->base != NULL)                                                                        \
                update_key_schedule((key_sched), (buf)->base + body_start, *(buf)->off - body_start);                              \
        });                                                                                                                        \
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

    outbuf_init(&outbuf, hkdf_label, &hkdf_label_off, sizeof(hkdf_label));

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

    if ((sched = malloc(sizeof(*sched))) == NULL)
        return NULL;
    if ((hash = algo->create()) == NULL) {
        free(sched);
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

static const uint8_t *parse_uint16(uint16_t *value, const uint8_t *src, const uint8_t *end)
{
    if (end - src < 2)
        return NULL;
    *value = readu16(src);
    return src + 2;
}

static int send_client_hello(ptls_t *tls, struct st_ptls_outbuf_t *outbuf)
{
    int ret;

    /* TODO postpone the generation of key_schedule until we receive ServerHello so that we can choose the best hash algo (note:
     * we'd need to retain the entire ClientHello) */
    tls->key_schedule = new_key_schedule(tls->ctx->crypto->cipher_suites->hash, ptls_iovec_init(NULL, 0));

    outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        /* legacy_version */
        outbuf_pushu16(outbuf, 0x0303);
        /* random_bytes */
        outbuf_reserve(outbuf, PTLS_HELLO_RANDOM_SIZE);
        if (outbuf->base != NULL)
            tls->ctx->crypto->random_bytes(outbuf->base + *outbuf->off, PTLS_HELLO_RANDOM_SIZE);
        *outbuf->off += PTLS_HELLO_RANDOM_SIZE;
        /* lecagy_session_id */
        outbuf_push_block(outbuf, 1, {});
        /* cipher_suites */
        outbuf_push_block(outbuf, 2, {
            ptls_cipher_suite_t *cs = tls->ctx->crypto->cipher_suites;
            for (; cs->id != UINT16_MAX; ++cs)
                outbuf_pushu16(outbuf, cs->id);
        });
        /* legacy_compression_methods */
        outbuf_push_block(outbuf, 1, { outbuf_push(outbuf, 0); });
        /* extensions */
        outbuf_push_block(outbuf, 2, {
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS,
                                  { outbuf_push_block(outbuf, 1, { outbuf_pushu16(outbuf, PTLS_PROTOCOL_VERSION_DRAFT16); }); });
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                outbuf_push_block(outbuf, 2, {
                    outbuf_pushu16(outbuf, PTLS_SIGNATURE_RSA_PSS_SHA256);
                    outbuf_pushu16(outbuf, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);
                });
            });
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, {
                ptls_key_exchange_algorithm_t *algo = tls->ctx->crypto->key_exchanges;
                outbuf_push_block(outbuf, 2, {
                    for (; algo->id != UINT16_MAX; ++algo)
                        outbuf_pushu16(outbuf, algo->id);
                });
            });
            outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                /* only sends the first algo at the moment */
                ptls_key_exchange_algorithm_t *algo = tls->ctx->crypto->key_exchanges;
                assert(algo->id != UINT16_MAX);
                ptls_iovec_t pubkey;
                if ((ret = algo->create(&tls->client.key_exchange, &pubkey)) != 0)
                    goto Exit;
                outbuf_push_block(outbuf, 2, {
                    outbuf_pushu16(outbuf, algo->id);
                    outbuf_push_block(outbuf, 2, { outbuf_pushv(outbuf, pubkey.base, pubkey.len); });
                });
                ptls_clear_memory(pubkey.base, pubkey.len);
                free(pubkey.base);
            });
        });
    });

    tls->state = PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO;
    ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

Exit:
    return ret;
}

static int decode_extensions(ptls_t *tls, const struct st_ptls_extension_decoder_t *decoders, void *arg, const uint8_t *src,
                             const uint8_t *end)
{
    uint16_t totallen, type, datalen;
    size_t i;
    int ret;

    if ((src = parse_uint16(&totallen, src, end)) == NULL || end - src != totallen)
        return PTLS_ALERT_DECODE_ERROR;

    while (src != end) {
        if ((src = parse_uint16(&type, src, end)) == NULL || (src = parse_uint16(&datalen, src, end)) == NULL ||
            datalen > end - src)
            return PTLS_ALERT_DECODE_ERROR;
        src += datalen;

        for (i = 0; decoders[i].type != UINT16_MAX; ++i) {
            if (decoders[i].type == type) {
                if ((ret = decoders[i].cb(tls, arg, src - datalen, src)) != 0)
                    return ret;
                goto Next;
            }
        }
    /* TODO check multiple occurences of unknown extensions */

    Next:;
    }

    return 0;
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

static int decode_server_name(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;

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

static int select_negotiated_group(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t len;

    if (ch->negotiated_group != NULL)
        return PTLS_ALERT_DECODE_ERROR;

    if ((src = parse_uint16(&len, src, end)) == NULL || end - src != len || len == 0 || len % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = readu16(src);
        ptls_key_exchange_algorithm_t *a = tls->ctx->crypto->key_exchanges;
        for (; a->id != UINT16_MAX; ++a) {
            if (a->id == id) {
                ch->negotiated_group = a;
                return 0;
            }
        }
    }

    return PTLS_ALERT_HANDSHAKE_FAILURE;
}

static int record_signature_algorithms(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t len;

    if ((src = parse_uint16(&len, src, end)) == NULL || end - src != len || len == 0 || len % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = readu16(src);
        if (ch->signature_algorithms.count < sizeof(ch->signature_algorithms.list) / sizeof(ch->signature_algorithms.list[0]))
            ch->signature_algorithms.list[ch->signature_algorithms.count++] = id;
    }

    return 0;
}

static int decode_client_hello_key_share(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t shareslen;

    if (ch->key_share.algorithm != NULL)
        return PTLS_ALERT_DECODE_ERROR;

    if ((src = parse_uint16(&shareslen, src, end)) == NULL || end - src != shareslen)
        return PTLS_ALERT_DECODE_ERROR;

    while (src != end) {
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

    if (ch->key_share.algorithm == NULL)
        ch->key_share.algorithm = &key_exchange_no_match;

    return 0;
}

static int select_version(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint8_t len;

    if (end - src < 3)
        return PTLS_ALERT_DECODE_ERROR;

    len = *src++;
    if ((end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t v = readu16(src);
        if (v == PTLS_PROTOCOL_VERSION_DRAFT16) {
            ch->selected_version = v;
            return 0;
        }
    }

    return PTLS_ALERT_HANDSHAKE_FAILURE;
}

static int record_cookie(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t len;

    if ((src = parse_uint16(&len, src, end)) == NULL)
        return PTLS_ALERT_DECODE_ERROR;
    if (end - src != len)
        return PTLS_ALERT_DECODE_ERROR;

    ch->cookie = ptls_iovec_init(src, len);
    return 0;
}

static int decode_server_hello(ptls_t *tls, struct st_ptls_server_hello_t *sh, const uint8_t *src, const uint8_t *end)
{
    int ret;

    *sh = (struct st_ptls_server_hello_t){};

    { /* check protocol version */
        uint16_t protver;
        if ((src = parse_uint16(&protver, src, end)) == NULL || protver != 0x0303)
            return PTLS_ALERT_DECODE_ERROR;
    }

    /* skip random */
    if (end - src < PTLS_HELLO_RANDOM_SIZE)
        return PTLS_ALERT_DECODE_ERROR;
    src += PTLS_HELLO_RANDOM_SIZE;

    { /* select cipher_suite */
        uint16_t csid;
        if ((src = parse_uint16(&csid, src, end)) == NULL)
            return PTLS_ALERT_DECODE_ERROR;
        for (sh->cipher_suite = tls->ctx->crypto->cipher_suites; sh->cipher_suite->id != UINT16_MAX; ++sh->cipher_suite)
            if (sh->cipher_suite->id == csid)
                break;
        if (sh->cipher_suite->id == UINT16_MAX)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    if ((ret = decode_extensions(tls, NULL, sh, src, end)) != 0)
        return ret;

    return 0;
}

static int decode_client_hello(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    int ret;

    *ch = (struct st_ptls_client_hello_t){};

    { /* check protocol version */
        uint16_t protver;
        if ((src = parse_uint16(&protver, src, end)) == NULL || protver != 0x0303)
            return PTLS_ALERT_DECODE_ERROR;
    }

    /* skip random */
    if (end - src < PTLS_HELLO_RANDOM_SIZE)
        return PTLS_ALERT_DECODE_ERROR;
    src += PTLS_HELLO_RANDOM_SIZE;

    { /* skip legacy_session_id */
        if (src == end)
            return PTLS_ALERT_DECODE_ERROR;
        uint8_t sesslen = *src++;
        if (sesslen > 32 || end - src < sesslen)
            return PTLS_ALERT_DECODE_ERROR;
        src += sesslen;
    }

    { /* decode and select from ciphersuites */
        uint16_t cslen;
        if ((src = parse_uint16(&cslen, src, end)) == NULL || end - src < cslen)
            return PTLS_ALERT_DECODE_ERROR;
        src += cslen;
        if ((ret = select_cipher_suite(tls->ctx->crypto, &ch->cipher_suite, src - cslen, src)) != 0)
            return ret;
    }

    /* decode legacy_compression_methods */
    if (end - src < 2)
        return PTLS_ALERT_DECODE_ERROR;
    if (*src == 0)
        return PTLS_ALERT_DECODE_ERROR;
    ch->compression_methods.count = *src++;
    ch->compression_methods.ids = src;
    src += ch->compression_methods.count;

    /* decode extensions */
    static const struct st_ptls_extension_decoder_t decoders[] = {
        {PTLS_EXTENSION_TYPE_SERVER_NAME, decode_server_name},
        {PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, select_negotiated_group},
        {PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, record_signature_algorithms},
        {PTLS_EXTENSION_TYPE_KEY_SHARE, decode_client_hello_key_share},
        {PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS, select_version},
        {PTLS_EXTENSION_TYPE_COOKIE, record_cookie},
        {UINT16_MAX},
    };
    if ((ret = decode_extensions(tls, decoders, ch, src, end)) != 0)
        return ret;

    /* check if client hello make sense */
    switch (ch->selected_version) {
    case PTLS_PROTOCOL_VERSION_DRAFT16:
        if (!(ch->compression_methods.count == 1 && ch->compression_methods.ids[0] == 0))
            return PTLS_ALERT_ILLEGAL_PARAMETER;
        /* cookie can be missing, quote section 4.2.2: When sending a HelloRetryRequest, the server MAY provide a “cookie” extension
         * to the client (this is an exception to the usual rule that the only extensions that may be sent are those that appear in
         * the ClientHello). */
        if (ch->negotiated_group == NULL || ch->signature_algorithms.count == 0 || ch->key_share.algorithm == NULL)
            return PTLS_ALERT_MISSING_EXTENSION;
        break;
    default:
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    return 0;
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
    uint8_t handshake_server_traffic_secret[PTLS_MAX_DIGEST_SIZE], finished_key[PTLS_MAX_DIGEST_SIZE];

    ptls_aead_context_t *enc = NULL;
    int ret;

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls, &ch, src, src + src_len)) != 0)
        goto Exit;

    /* send HelloRetryRequest or abort the handshake if failed to obtain the key */
    if (ch.key_share.algorithm == &key_exchange_no_match) {
        if (ch.negotiated_group != NULL) {
            outbuf_push_handshake(outbuf, NULL, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, {
                outbuf_pushu16(outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
                outbuf_push_block(outbuf, 2, {
                    outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,
                                          { outbuf_pushu16(outbuf, ch.negotiated_group->id); });
                    /* Section 4.2.3: Servers which are authenticating via a certificate MUST indicate so by sending the client an
                     * empty "signature_algorithms" extension. */
                    outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {});
                });
            });
            ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
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
    if ((ret = ch.key_share.algorithm->exchange(&pubkey, &ecdh_secret, ch.key_share.peer)) != 0)
        goto Exit;

    /* create key schedule and feed the initial values supplied from the client */
    assert(tls->key_schedule == NULL);
    tls->key_schedule = new_key_schedule(ch.cipher_suite->hash, ptls_iovec_init(NULL, 0));
    roll_key_schedule(tls->key_schedule, ptls_iovec_init(NULL, 0));
    update_key_schedule(tls->key_schedule, src, src_len);

    /* send ServerHello */
    outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {
        outbuf_pushu16(outbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
        outbuf_reserve(outbuf, PTLS_HELLO_RANDOM_SIZE);
        if (outbuf->base != NULL)
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
    if ((enc = ptls_aead_new(ch.cipher_suite->aead, ch.cipher_suite->hash, 1, handshake_server_traffic_secret,
                             "handshake key expansion")) == NULL)
        goto Exit;

    /* send EncryptedExtensions */
    outbuf_encrypt(outbuf, enc, {
        outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
            outbuf_push_block(outbuf, 2, { outbuf_push_extension(outbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {}); });
        });
    });

    /* send Certificate */
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

    outbuf_encrypt(outbuf, enc, {
        outbuf_push_handshake(outbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
            outbuf_reserve(outbuf, tls->key_schedule->algo->digest_size);
            if (outbuf->base != NULL) {
                ptls_hash_context_t *hmac;
                if (hkdf_expand_label(tls->key_schedule->algo, finished_key, tls->key_schedule->algo->digest_size,
                                      ptls_iovec_init(handshake_server_traffic_secret, tls->key_schedule->algo->digest_size),
                                      "finished", "", ptls_iovec_init(NULL, 0)) != 0)
                    goto Exit;
                if ((hmac = ptls_hmac_create(tls->key_schedule->algo, finished_key, tls->key_schedule->algo->digest_size)) == NULL)
                    goto Exit;
                uint8_t d[PTLS_MAX_DIGEST_SIZE];
                tls->key_schedule->msghash->final(tls->key_schedule->msghash, d, PTLS_HASH_FINAL_MODE_SNAPSHOT);
                hmac->update(hmac, d, tls->key_schedule->algo->digest_size);
                ptls_clear_memory(d, sizeof(d));
                hmac->update(hmac, tls->key_schedule->hashed_resumption_context, tls->key_schedule->algo->digest_size);
                hmac->final(hmac, outbuf->base + *outbuf->off, PTLS_HASH_FINAL_MODE_FREE);
            }
            *outbuf->off += tls->key_schedule->algo->digest_size;
        });
    });

    ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

Exit:
    free(pubkey.base);
    free(ecdh_secret.base);
    ptls_clear_memory(handshake_server_traffic_secret, sizeof(handshake_server_traffic_secret));
    ptls_clear_memory(finished_key, sizeof(finished_key));
    if (enc != NULL)
        ptls_aead_free(enc);
    return ret;
}

static int handle_server_hello(ptls_t *tls, struct st_ptls_outbuf_t *outbuf, const uint8_t *src, size_t src_len)
{
    return PTLS_ALERT_DECODE_ERROR;
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

ptls_t *ptls_new(ptls_context_t *ctx, const char *server_name)
{
    ptls_t *tls;

    if ((tls = malloc(sizeof(*tls))) == NULL)
        return NULL;

    *tls = (ptls_t){ctx};
    if (server_name != NULL) {
        tls->state = PTLS_STATE_CLIENT_HANDSHAKE_START;
        if ((tls->client.server_name = strdup(server_name)) == NULL)
            goto Fail;
    } else {
        tls->state = PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO;
    }

    return tls;

Fail:
    ptls_free(tls);
    return NULL;
}

void ptls_free(ptls_t *tls)
{
    inbuf_dispose(&tls->recbuf);
    inbuf_dispose(&tls->handshakebuf);
    if (tls->key_schedule != NULL)
        free_key_schedule(tls->key_schedule);
    free(tls->client.server_name);
    free(tls);
}

ptls_context_t *ptls_get_context(ptls_t *tls)
{
    return tls->ctx;
}

static int extract_handshake_message(uint8_t *type, ptls_iovec_t *body, const uint8_t *src, size_t len)
{
    if (len < 4)
        return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

    body->len = readu24(src + 1);

    if (body->len > len - 4) {
        return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
    } else if (body->len < len - 4) {
        return PTLS_ALERT_DECODE_ERROR;
    }

    *type = *src;
    body->base = (uint8_t *)src + 4;
    return 0;
}

int ptls_handshake(ptls_t *tls, const void *input, size_t *inlen, void *output, size_t *outlen)
{
    struct st_ptls_outbuf_t outbuf;

    outbuf_init(&outbuf, output, outlen, *outlen);

    /* special handling for initiating the handshake */
    if (tls->state == PTLS_STATE_CLIENT_HANDSHAKE_START) {
        assert(input == NULL);
        return send_client_hello(tls, &outbuf);
    }

    const uint8_t *src = input, *src_end = src + *inlen;
    struct st_ptls_record_t rec;
    uint8_t hstype;
    ptls_iovec_t hsbody;
    int ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

    while (ret == PTLS_ERROR_HANDSHAKE_IN_PROGRESS && src != src_end) {
        /* extract the first record */
        if ((src = parse_record(tls, &rec, &ret, src, src_end)) == NULL)
            break;
        if (rec.fragment == NULL)
            break;

        /* validate as handshake message (and retain if partial) */
        if (rec.type != PTLS_CONTENT_TYPE_HANDSHAKE) {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            break;
        }
        if (tls->handshakebuf.base == NULL && extract_handshake_message(&hstype, &hsbody, rec.fragment, rec.length) == 0) {
            /* first path; successfully extracted the handshake message from a single record */
        } else {
            /* handshake message split into multiple records, concat them into a buffer and handle when complete */
            /* TODO introduce ceiling for max size */
            if ((ret = inbuf_prepare(&tls->handshakebuf, tls->handshakebuf.len + rec.length)) != 0)
                break;
            memcpy(tls->handshakebuf.base + tls->handshakebuf.len, rec.fragment, rec.length);
            tls->handshakebuf.len += rec.length;
            if ((ret = extract_handshake_message(&hstype, &hsbody, tls->handshakebuf.base, tls->handshakebuf.len)) != 0)
                break;
        }

        switch (tls->state) {
        case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
            if (hstype == PTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
                ret = handle_client_hello(tls, &outbuf, hsbody.base, hsbody.len);
            } else {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            }
            break;
        case PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
            if (hstype == PTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
                ret = handle_server_hello(tls, &outbuf, hsbody.base, hsbody.len);
            } else {
                ret = PTLS_ALERT_HANDSHAKE_FAILURE;
            }
            break;
        default:
            assert(!"unexpected state");
            break;
        }
    }

    assert(!outbuf.is_allocated || "TODO implement");
    *inlen = src - (const uint8_t *)input;

    return ret;
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

ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *label)
{
    ptls_aead_context_t *ctx;
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    int ret;

    if ((ctx = (ptls_aead_context_t *)malloc(offsetof(ptls_aead_context_t, static_iv) + aead->iv_size)) == NULL)
        return NULL;

    *ctx = (ptls_aead_context_t){NULL, NULL, NULL, aead, 0};

    if ((ret = get_traffic_key(hash, key, hash->digest_size, label, 0, secret)) != 0)
        goto Exit;
    if ((ret = get_traffic_key(hash, ctx->static_iv, aead->iv_size, label, 1, secret)) != 0)
        goto Exit;
    ret = aead->setup_crypto(ctx, is_enc, key);

Exit:
    ptls_clear_memory(key, aead->key_size);
    if (ret != 0) {
        ptls_clear_memory(ctx->static_iv, aead->iv_size);
        free(ctx);
        ctx = NULL;
    }

    return ctx;
}

void ptls_aead_free(ptls_aead_context_t *ctx)
{
    ctx->dispose_crypto(ctx);
    ptls_clear_memory(ctx->static_iv, ctx->algo->iv_size);
    free(ctx);
}

int ptls_aead_transform(ptls_aead_context_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen)
{
    uint8_t iv[PTLS_MAX_IV_SIZE];
    size_t iv_size = ctx->algo->iv_size;
    int ret;

    { /* build iv */
        const uint8_t *s = ctx->static_iv;
        uint8_t *d = iv;
        size_t i = iv_size - 8;
        for (; i != 0; --i)
            *d++ = *s++;
        i = 64;
        do {
            i -= 8;
            *d++ = *s++ ^ (uint8_t)(ctx->seq >> i);
        } while (i != 0);
    }

    if ((ret = ctx->do_transform(ctx, output, outlen, input, inlen, iv)) != 0)
        return ret;

    ++ctx->seq;
    return 0;
}

static void clear_memory(void *p, size_t len)
{
    memset(p, 0, len);
}

void (*volatile ptls_clear_memory)(void *p, size_t len) = clear_memory;
