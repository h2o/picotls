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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"

#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384
#define PTLS_MAX_ENCRYPTED_RECORD_SIZE (16384 + 256)

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

#define PTLS_HANDSHAKE_HEADER_SIZE 4

#define PTLS_EXTENSION_TYPE_SERVER_NAME 0
#define PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS 10
#define PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS 13
#define PTLS_EXTENSION_TYPE_KEY_SHARE 40
#define PTLS_EXTENSION_TYPE_PRE_SHARED_KEY 41
#define PTLS_EXTENSION_TYPE_EARLY_DATA 42
#define PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS 43
#define PTLS_EXTENSION_TYPE_COOKIE 44

#define PTLS_PROTOCOL_VERSION_DRAFT16 0x7f16

#define PTLS_ALERT_LEVEL_WARNING 1
#define PTLS_ALERT_LEVEL_FATAL 2

struct st_ptls_protection_context_t {
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    ptls_aead_context_t *aead;
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
        PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE,
        PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY,
        PTLS_STATE_CLIENT_EXPECT_FINISHED,
        PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO,
        /* ptls_send can be called if the state is below here */
        PTLS_STATE_SERVER_EXPECT_FINISHED,
        PTLS_STATE_POST_HANDSHAKE
    } state;
    /**
     * receive buffers
     */
    struct {
        struct st_ptls_buffer_t rec;
        struct st_ptls_buffer_t mess;
    } recvbuf;
    /**
     * key schedule
     */
    struct st_ptls_key_schedule_t *key_schedule;
    /**
     * values used for record protection
     */
    struct {
        struct st_ptls_protection_context_t recv;
        struct st_ptls_protection_context_t send;
    } protection_ctx;
    /**
     * misc.
     */
    struct {
        struct {
            char *server_name;
            struct {
                ptls_key_exchange_algorithm_t *algo;
                ptls_key_exchange_context_t *ctx;
            } key_exchange;
        } client;
    };
};

struct st_ptls_record_t {
    uint8_t type;
    uint16_t version;
    size_t length;
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
    ptls_iovec_t peerkey;
};

struct st_ptls_key_schedule_t {
    ptls_hash_algorithm_t *algo;
    ptls_hash_context_t *msghash;
    unsigned generation; /* early secret (1), hanshake secret (2), master secret (3) */
    uint8_t secret[PTLS_MAX_DIGEST_SIZE];
    uint8_t hashed_resumption_context[PTLS_MAX_DIGEST_SIZE];
};

struct st_ptls_extension_decoder_t {
    uint16_t type;
    int (*cb)(ptls_t *tls, void *arg, const uint8_t *src, const uint8_t *end);
};

static uint8_t zeroes_of_max_digest_size[PTLS_MAX_DIGEST_SIZE] = {};
static ptls_key_exchange_algorithm_t key_exchange_no_match;

static uint16_t ntoh16(const uint8_t *src)
{
    return (uint16_t)src[0] << 8 | src[1];
}

static uint32_t ntoh24(const uint8_t *src)
{
    return (uint32_t)src[0] << 16 | (uint32_t)src[1] << 8 | src[2];
}

void ptls_buffer__release_memory(struct st_ptls_buffer_t *buf)
{
    if (buf->base == NULL)
        return;

    ptls_clear_memory(buf->base, buf->off);
    if (buf->is_allocated)
        free(buf->base);
    buf->base = NULL;
}

int ptls_buffer_reserve(struct st_ptls_buffer_t *buf, size_t delta)
{
    if (buf->base == NULL)
        return PTLS_ERROR_NO_MEMORY;

    if (buf->capacity < buf->off + delta) {
        uint8_t *newp;
        size_t new_capacity = buf->capacity * 2;
        if (new_capacity < 1024)
            new_capacity = 1024;
        if ((newp = malloc(new_capacity)) == NULL) {
            ptls_buffer__release_memory(buf);
            return PTLS_ERROR_NO_MEMORY;
        }
        memcpy(newp, buf->base, buf->off);
        ptls_buffer__release_memory(buf);
        buf->base = newp;
        buf->capacity = new_capacity;
        buf->is_allocated = 1;
    }

    return 0;
}

#define buffer_push(buf, ...) buffer_pushv((buf), (uint8_t[]){__VA_ARGS__}, sizeof((uint8_t[]){__VA_ARGS__}))

static void buffer_pushv(struct st_ptls_buffer_t *buf, const void *src, size_t len)
{
    ptls_buffer_reserve(buf, len);
    if (buf->base == NULL)
        return;
    memcpy(buf->base + buf->off, src, len);
    buf->off += len;
}

static void buffer_push16(struct st_ptls_buffer_t *buf, uint16_t v)
{
    buffer_push(buf, (uint8_t)(v >> 8), (uint8_t)v);
}

static void buffer_encrypt_record(struct st_ptls_buffer_t *buf, size_t rec_start, ptls_aead_context_t *aead)
{
    if (buf->base == NULL)
        return;

    uint8_t encrypted[PTLS_MAX_ENCRYPTED_RECORD_SIZE];
    size_t enclen, bodylen = buf->off - rec_start - 5;

    assert(bodylen <= PTLS_MAX_PLAINTEXT_RECORD_SIZE);

    int ret = ptls_aead_transform(aead, encrypted, &enclen, buf->base + rec_start + 5, bodylen, buf->base[rec_start]);
    assert(ret == 0);

    buf->off = rec_start;
    buffer_push(buf, PTLS_CONTENT_TYPE_APPDATA, 3, 1);
    buffer_push16(buf, enclen);
    buffer_pushv(buf, encrypted, enclen);
}

#define buffer_push_block(buf, _capacity, block)                                                                                   \
    do {                                                                                                                           \
        size_t capacity = (_capacity);                                                                                             \
        buffer_pushv((buf), (uint8_t *)"\0\0\0\0\0\0\0", capacity);                                                                \
        size_t body_start = (buf)->off;                                                                                            \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        if ((buf)->base != NULL) {                                                                                                 \
            size_t body_size = (buf)->off - body_start;                                                                            \
            for (; capacity != 0; --capacity) {                                                                                    \
                (buf)->base[body_start - capacity] = (uint8_t)(body_size >> (8 * (capacity - 1)));                                 \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

#define buffer_push_record(buf, type, block)                                                                                       \
    do {                                                                                                                           \
        buffer_push((buf), (type), PTLS_RECORD_VERSION_MAJOR, PTLS_RECORD_VERSION_MINOR);                                          \
        buffer_push_block((buf), 2, block);                                                                                        \
    } while (0)

#define buffer_encrypt(buf, enc, block)                                                                                            \
    do {                                                                                                                           \
        size_t rec_start = (buf)->off;                                                                                             \
        do {                                                                                                                       \
            block                                                                                                                  \
        } while (0);                                                                                                               \
        buffer_encrypt_record((buf), rec_start, (enc));                                                                            \
    } while (0);

#define buffer_push_handshake(buf, key_sched, type, block)                                                                         \
    buffer_push_record((buf), PTLS_CONTENT_TYPE_HANDSHAKE, {                                                                       \
        size_t mess_start = (buf)->off;                                                                                            \
        buffer_push((buf), (type));                                                                                                \
        buffer_push_block((buf), 3, {                                                                                              \
            do {                                                                                                                   \
                block                                                                                                              \
            } while (0);                                                                                                           \
        });                                                                                                                        \
        if ((key_sched) != NULL && (buf)->base != NULL)                                                                            \
            key_schedule_update_hash((key_sched), (buf)->base + mess_start, (buf)->off - mess_start);                              \
    })

#define buffer_push_extension(buf, type, block)                                                                                    \
    do {                                                                                                                           \
        buffer_push16((buf), (type));                                                                                              \
        buffer_push_block((buf), 2, block);                                                                                        \
    } while (0);

static int hkdf_expand_label(ptls_hash_algorithm_t *algo, void *output, size_t outlen, ptls_iovec_t secret, const char *label1,
                             const char *label2, ptls_iovec_t hash_value)
{
    struct st_ptls_buffer_t hkdf_label;
    uint8_t hkdf_label_buf[514];

    ptls_buffer_init(&hkdf_label, hkdf_label_buf, sizeof(hkdf_label_buf));

    buffer_push16(&hkdf_label, outlen);
    buffer_push_block(&hkdf_label, 1, {
        const char *prefix = "TLS 1.3, ";
        buffer_pushv(&hkdf_label, prefix, strlen(prefix));
        buffer_pushv(&hkdf_label, label1, strlen(label1));
        buffer_pushv(&hkdf_label, ", ", 2);
        buffer_pushv(&hkdf_label, label2, strlen(label2));
    });
    buffer_push_block(&hkdf_label, 1, { buffer_pushv(&hkdf_label, hash_value.base, hash_value.len); });

    int ret = ptls_hkdf_expand(algo, output, outlen, secret, ptls_iovec_init(hkdf_label.base, hkdf_label.off));

    ptls_buffer_dispose(&hkdf_label);
    return ret;
}

static struct st_ptls_key_schedule_t *key_schedule_new(ptls_hash_algorithm_t *algo, ptls_iovec_t resumption_context)
{
    struct st_ptls_key_schedule_t *sched = NULL;
    ptls_hash_context_t *hash = NULL;

    if ((sched = malloc(sizeof(*sched))) == NULL)
        return NULL;
    if ((hash = algo->create()) == NULL) {
        free(sched);
        return NULL;
    }

    *sched = (struct st_ptls_key_schedule_t){algo, hash};

    if (resumption_context.base == NULL)
        resumption_context = ptls_iovec_init(zeroes_of_max_digest_size, sched->algo->digest_size);
    hash->update(hash, resumption_context.base, resumption_context.len);
    hash->final(hash, sched->hashed_resumption_context, PTLS_HASH_FINAL_MODE_RESET);

    return sched;
}

static void key_schedule_free(struct st_ptls_key_schedule_t *sched)
{
    sched->msghash->final(sched->msghash, NULL, PTLS_HASH_FINAL_MODE_FREE);
    free(sched);
}

static int key_schedule_extract(struct st_ptls_key_schedule_t *sched, ptls_iovec_t ikm)
{
    if (ikm.base == NULL)
        ikm = ptls_iovec_init(zeroes_of_max_digest_size, sched->algo->digest_size);

    ++sched->generation;
    int ret = ptls_hkdf_extract(sched->algo, sched->secret, ptls_iovec_init(sched->secret, sched->algo->digest_size), ikm);
    fprintf(stderr, "%s: %u, %02x%02x\n", __FUNCTION__, sched->generation, (int)sched->secret[0], (int)sched->secret[1]);
    return ret;
}

static void key_schedule_update_hash(struct st_ptls_key_schedule_t *sched, const uint8_t *msg, size_t msglen)
{
    fprintf(stderr, "%s:%zu\n", __FUNCTION__, msglen);
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

static void dispose_protection_context(struct st_ptls_protection_context_t *ctx)
{
    /* also used to clear sensible data if setup failed */
    ptls_clear_memory(ctx->secret, sizeof(ctx->secret));
    if (ctx->aead != NULL) {
        ptls_aead_free(ctx->aead);
        ctx->aead = NULL;
    }
}

static int setup_protection_context(struct st_ptls_protection_context_t *ctx, struct st_ptls_key_schedule_t *sched,
                                    const char *secret_label, ptls_aead_algorithm_t *aead, int is_enc, const char *aead_label)
{
    int ret;

    dispose_protection_context(ctx);

    if ((ret = derive_secret(sched, ctx->secret, secret_label)) != 0)
        goto Fail;
    if ((ctx->aead = ptls_aead_new(aead, sched->algo, is_enc, ctx->secret, aead_label)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY; /* TODO obtain error from ptls_aead_new */
        goto Fail;
    }
    fprintf(stderr, "[%s,%s] %02x%02x,%02x%02x\n", secret_label, aead_label, (unsigned)ctx->secret[0], (unsigned)ctx->secret[1],
            (unsigned)ctx->aead->static_iv[0], (unsigned)ctx->aead->static_iv[1]);

    return 0;
Fail:
    dispose_protection_context(ctx);
    return ret;
}

static int send_alert(ptls_t *tls, ptls_buffer_t *sendbuf, uint8_t level, uint8_t description)
{
    size_t rec_start = sendbuf->off;
    buffer_push_record(sendbuf, PTLS_CONTENT_TYPE_ALERT, { buffer_push(sendbuf, level, description); });
    if (tls->protection_ctx.send.aead != NULL)
        buffer_encrypt_record(sendbuf, rec_start, tls->protection_ctx.send.aead);
    return sendbuf->base != NULL;
}

static int calc_verify_data(void *output, struct st_ptls_key_schedule_t *sched, const void *secret)
{
    ptls_hash_context_t *hmac;
    uint8_t digest[PTLS_MAX_DIGEST_SIZE];
    int ret;

    if ((ret = hkdf_expand_label(sched->algo, digest, sched->algo->digest_size, ptls_iovec_init(secret, sched->algo->digest_size),
                                 "finished", "", ptls_iovec_init(NULL, 0))) != 0)
        return ret;
    if ((hmac = ptls_hmac_create(sched->algo, digest, sched->algo->digest_size)) == NULL) {
        ptls_clear_memory(digest, sizeof(digest));
        return PTLS_ERROR_NO_MEMORY;
    }

    sched->msghash->final(sched->msghash, digest, PTLS_HASH_FINAL_MODE_SNAPSHOT);
    fprintf(stderr, "%s: %02x%02x,%02x%02x\n", __FUNCTION__, ((uint8_t *)secret)[0], ((uint8_t *)secret)[1], digest[0], digest[1]);
    hmac->update(hmac, digest, sched->algo->digest_size);
    ptls_clear_memory(digest, sizeof(digest));
    hmac->update(hmac, sched->hashed_resumption_context, sched->algo->digest_size);
    hmac->final(hmac, output, PTLS_HASH_FINAL_MODE_FREE);

    return 0;
}

static int verify_finished(ptls_t *tls, ptls_iovec_t message)
{
    uint8_t verify_data[PTLS_MAX_DIGEST_SIZE];
    int ret = 0;

    if (PTLS_HANDSHAKE_HEADER_SIZE + tls->key_schedule->algo->digest_size != message.len)
        return PTLS_ALERT_DECODE_ERROR;

    if ((ret = calc_verify_data(verify_data, tls->key_schedule, tls->protection_ctx.recv.secret)) != 0)
        goto Exit;
    if (memcmp(message.base + PTLS_HANDSHAKE_HEADER_SIZE, verify_data, tls->key_schedule->algo->digest_size) != 0) {
        ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        goto Exit;
    }

Exit:
    ptls_clear_memory(verify_data, sizeof(verify_data));
    return ret;
}

static int send_finished(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    int ret;

    buffer_encrypt(sendbuf, tls->protection_ctx.send.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_FINISHED, {
            if ((ret = ptls_buffer_reserve(sendbuf, tls->key_schedule->algo->digest_size)) != 0)
                return ret;
            if ((ret = calc_verify_data(sendbuf->base + sendbuf->off, tls->key_schedule, tls->protection_ctx.send.secret)) != 0)
                return ret;
            sendbuf->off += tls->key_schedule->algo->digest_size;
        });
    });

    return 0;
}

static const uint8_t *parse_uint16(uint16_t *value, const uint8_t *src, const uint8_t *end)
{
    if (end - src < 2)
        return NULL;
    *value = ntoh16(src);
    return src + 2;
}

static int send_client_hello(ptls_t *tls, ptls_buffer_t *sendbuf)
{
    int ret;

    /* TODO postpone the generation of key_schedule until we receive ServerHello so that we can choose the best hash algo (note:
     * we'd need to retain the entire ClientHello) */
    tls->key_schedule = key_schedule_new(tls->ctx->crypto->cipher_suites->hash, ptls_iovec_init(NULL, 0));
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        return ret;

    buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CLIENT_HELLO, {
        /* legacy_version */
        buffer_push16(sendbuf, 0x0303);
        /* random_bytes */
        if ((ret = ptls_buffer_reserve(sendbuf, PTLS_HELLO_RANDOM_SIZE)) != 0)
            return ret;
        tls->ctx->crypto->random_bytes(sendbuf->base + sendbuf->off, PTLS_HELLO_RANDOM_SIZE);
        sendbuf->off += PTLS_HELLO_RANDOM_SIZE;
        /* lecagy_session_id */
        buffer_push_block(sendbuf, 1, {});
        /* cipher_suites */
        buffer_push_block(sendbuf, 2, {
            ptls_cipher_suite_t *cs = tls->ctx->crypto->cipher_suites;
            for (; cs->id != UINT16_MAX; ++cs)
                buffer_push16(sendbuf, cs->id);
        });
        /* legacy_compression_methods */
        buffer_push_block(sendbuf, 1, { buffer_push(sendbuf, 0); });
        /* extensions */
        buffer_push_block(sendbuf, 2, {
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS,
                                  { buffer_push_block(sendbuf, 1, { buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT16); }); });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {
                buffer_push_block(sendbuf, 2, {
                    buffer_push16(sendbuf, PTLS_SIGNATURE_RSA_PSS_SHA256);
                    buffer_push16(sendbuf, PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, {
                ptls_key_exchange_algorithm_t *algo = tls->ctx->crypto->key_exchanges;
                buffer_push_block(sendbuf, 2, {
                    for (; algo->id != UINT16_MAX; ++algo)
                        buffer_push16(sendbuf, algo->id);
                });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                /* only sends the first algo at the moment */
                ptls_key_exchange_algorithm_t *algo = tls->ctx->crypto->key_exchanges;
                assert(algo->id != UINT16_MAX);
                ptls_iovec_t pubkey;
                if ((ret = algo->create(&tls->client.key_exchange.ctx, &pubkey)) != 0)
                    return ret;
                tls->client.key_exchange.algo = algo;
                buffer_push_block(sendbuf, 2, {
                    buffer_push16(sendbuf, algo->id);
                    buffer_push_block(sendbuf, 2, { buffer_pushv(sendbuf, pubkey.base, pubkey.len); });
                });
                ptls_clear_memory(pubkey.base, pubkey.len);
                free(pubkey.base);
            });
        });
    });

    tls->state = PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO;
    return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
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

static const uint8_t *decode_key_share_entry(uint16_t *group, ptls_iovec_t *key_exchange, const uint8_t *src, const uint8_t *end)
{
    uint16_t keyexlen;

    if ((src = parse_uint16(group, src, end)) == NULL || (src = parse_uint16(&keyexlen, src, end)) == NULL || end - src < 1 ||
        end - src < keyexlen)
        return NULL;
    *key_exchange = ptls_iovec_init(src, keyexlen);
    src += keyexlen;

    return src;
}

static int return_decode_error_for_extension(ptls_t *tls, void *_sh, const uint8_t *src, const uint8_t *end)
{
    return PTLS_ALERT_DECODE_ERROR;
}

static int expect_empty_extension(ptls_t *tls, void *_sh, const uint8_t *src, const uint8_t *end)
{
    if (src != end)
        return PTLS_ALERT_DECODE_ERROR;
    return 0;
}

static int server_hello_record_key_share(ptls_t *tls, void *_sh, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_server_hello_t *sh = (struct st_ptls_server_hello_t *)_sh;
    uint16_t group;
    ptls_iovec_t keyex;

    if ((src = decode_key_share_entry(&group, &keyex, src, end)) == NULL || src != end)
        return PTLS_ALERT_DECODE_ERROR;
    if (tls->client.key_exchange.algo->id != group)
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    sh->peerkey = keyex;

    return 0;
}

static int decode_server_hello(ptls_t *tls, struct st_ptls_server_hello_t *sh, const uint8_t *src, const uint8_t *end)
{
    int ret;

    *sh = (struct st_ptls_server_hello_t){};

    { /* check protocol version */
        uint16_t protver;
        if ((src = parse_uint16(&protver, src, end)) == NULL || protver != PTLS_PROTOCOL_VERSION_DRAFT16)
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

    static const struct st_ptls_extension_decoder_t decoders[] = {
        {PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS, return_decode_error_for_extension},
        {PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, expect_empty_extension},
        {PTLS_EXTENSION_TYPE_KEY_SHARE, server_hello_record_key_share},
        {UINT16_MAX}};
    if ((ret = decode_extensions(tls, decoders, sh, src, end)) != 0)
        return ret;

    if (sh->cipher_suite == NULL || sh->peerkey.base == NULL)
        return PTLS_ALERT_ILLEGAL_PARAMETER;

    return 0;
}

static int client_handle_hello(ptls_t *tls, ptls_iovec_t message)
{
    struct st_ptls_server_hello_t sh;
    ptls_iovec_t ecdh_secret;
    int ret;

    if ((ret = decode_server_hello(tls, &sh, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        return ret;

    if ((ret = tls->client.key_exchange.ctx->on_exchange(tls->client.key_exchange.ctx, &ecdh_secret, sh.peerkey)) != 0)
        return ret;

    if ((ret = key_schedule_extract(tls->key_schedule, ecdh_secret)) != 0)
        return ret;

    if ((ret = setup_protection_context(&tls->protection_ctx.send, tls->key_schedule, "client handshake traffic secret",
                                        sh.cipher_suite->aead, 1, "handshake key expansion")) != 0)
        return ret;
    if ((ret = setup_protection_context(&tls->protection_ctx.recv, tls->key_schedule, "server handshake traffic secret",
                                        sh.cipher_suite->aead, 0, "handshake key expansion")) != 0)
        return ret;

    tls->state = PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS;
    return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
}

static int client_handle_finished(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message)
{
    struct st_ptls_protection_context_t send_ctx = {{0}};
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        return ret;
    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    /* update traffic keys by using messages upto ServerFinished, but commission them after sending ClientFinished */
    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        return ret;
    if ((ret = setup_protection_context(&tls->protection_ctx.recv, tls->key_schedule, "server application traffic secret",
                                        tls->protection_ctx.recv.aead->algo, 0, "application data key expansion")) != 0)
        return ret;
    if ((ret = setup_protection_context(&send_ctx, tls->key_schedule, "client application traffic secret",
                                        tls->protection_ctx.send.aead->algo, 1, "application data key expansion")) != 0)
        return ret;

    ret = send_finished(tls, sendbuf);

    dispose_protection_context(&tls->protection_ctx.send);
    tls->protection_ctx.send = send_ctx;
    ptls_clear_memory(&send_ctx, sizeof(send_ctx));

    tls->state = PTLS_STATE_POST_HANDSHAKE;

    return ret;
}

static int client_hello_decode_server_name(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
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

static int client_hello_select_negotiated_group(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t len;

    if (ch->negotiated_group != NULL)
        return PTLS_ALERT_DECODE_ERROR;

    if ((src = parse_uint16(&len, src, end)) == NULL || end - src != len || len == 0 || len % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = ntoh16(src);
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

static int client_hello_record_signature_algorithms(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t len;

    if ((src = parse_uint16(&len, src, end)) == NULL || end - src != len || len == 0 || len % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t id = ntoh16(src);
        if (ch->signature_algorithms.count < sizeof(ch->signature_algorithms.list) / sizeof(ch->signature_algorithms.list[0]))
            ch->signature_algorithms.list[ch->signature_algorithms.count++] = id;
    }

    return 0;
}

static int client_hello_decode_key_share(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint16_t shareslen;

    if (ch->key_share.algorithm != NULL)
        return PTLS_ALERT_DECODE_ERROR;

    if ((src = parse_uint16(&shareslen, src, end)) == NULL || end - src != shareslen)
        return PTLS_ALERT_DECODE_ERROR;

    while (src != end) {
        uint16_t group;
        ptls_iovec_t key_exchange;
        if ((src = decode_key_share_entry(&group, &key_exchange, src, end)) == NULL)
            return PTLS_ALERT_DECODE_ERROR;
        if (ch->key_share.algorithm == NULL) {
            ptls_key_exchange_algorithm_t *a = tls->ctx->crypto->key_exchanges;
            for (; a->id != UINT16_MAX; ++a) {
                if (a->id == group) {
                    ch->key_share.algorithm = a;
                    ch->key_share.peer = key_exchange;
                    break;
                }
            }
        }
    }
    if (ch->key_share.algorithm == NULL)
        ch->key_share.algorithm = &key_exchange_no_match;

    return 0;
}

static int client_hello_select_version(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
{
    struct st_ptls_client_hello_t *ch = (struct st_ptls_client_hello_t *)_ch;
    uint8_t len;

    if (end - src < 3)
        return PTLS_ALERT_DECODE_ERROR;

    len = *src++;
    if ((end - src) % 2 != 0)
        return PTLS_ALERT_DECODE_ERROR;

    for (; src != end; src += 2) {
        uint16_t v = ntoh16(src);
        if (v == PTLS_PROTOCOL_VERSION_DRAFT16) {
            ch->selected_version = v;
            return 0;
        }
    }

    return PTLS_ALERT_HANDSHAKE_FAILURE;
}

static int client_hello_record_cookie(ptls_t *tls, void *_ch, const uint8_t *src, const uint8_t *end)
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

static int decode_client_hello(ptls_t *tls, struct st_ptls_client_hello_t *ch, const uint8_t *src, const uint8_t *end)
{
    int ret;

    *ch = (struct st_ptls_client_hello_t){};

    { /* check protocol version */
        uint16_t protver;
        if ((src = parse_uint16(&protver, src, end)) == NULL || protver != 0x0303)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
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
        if ((src = parse_uint16(&cslen, src, end)) == NULL || end - src < cslen || cslen == 0 || cslen % 2 != 0)
            return PTLS_ALERT_DECODE_ERROR;
        for (; cslen != 0; cslen -= 2, src += 2) {
            uint16_t id = ntoh16(src);
            ptls_cipher_suite_t *a = tls->ctx->crypto->cipher_suites;
            for (; a->id != UINT16_MAX; ++a) {
                if (a->id == id) {
                    ch->cipher_suite = a;
                    break;
                }
            }
        }
        if (ch->cipher_suite == NULL)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
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
        {PTLS_EXTENSION_TYPE_SERVER_NAME, client_hello_decode_server_name},
        {PTLS_EXTENSION_TYPE_SUPPORTED_GROUPS, client_hello_select_negotiated_group},
        {PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, client_hello_record_signature_algorithms},
        {PTLS_EXTENSION_TYPE_KEY_SHARE, client_hello_decode_key_share},
        {PTLS_EXTENSION_TYPE_SUPPORTED_VERSIONS, client_hello_select_version},
        {PTLS_EXTENSION_TYPE_COOKIE, client_hello_record_cookie},
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

static int server_handle_hello(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message)
{
    struct st_ptls_client_hello_t ch;
    ptls_iovec_t *certs;
    size_t num_certs;
    uint16_t sign_algorithm;
    int (*signer)(void *, ptls_iovec_t *, ptls_iovec_t);
    void *signer_data;
    ptls_iovec_t pubkey = {}, ecdh_secret = {};
    uint8_t finished_key[PTLS_MAX_DIGEST_SIZE];
    int ret;

    /* decode ClientHello */
    if ((ret = decode_client_hello(tls, &ch, message.base + PTLS_HANDSHAKE_HEADER_SIZE, message.base + message.len)) != 0)
        goto Exit;

    /* send HelloRetryRequest or abort the handshake if failed to obtain the key */
    if (ch.key_share.algorithm == &key_exchange_no_match) {
        if (ch.negotiated_group != NULL) {
            buffer_push_handshake(sendbuf, NULL, PTLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST, {
                buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
                buffer_push_block(sendbuf, 2, {
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE,
                                          { buffer_push16(sendbuf, ch.negotiated_group->id); });
                    /* Section 4.2.3: Servers which are authenticating via a certificate MUST indicate so by sending the client an
                     * empty "signature_algorithms" extension. */
                    buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {});
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

    /* create key schedule, feed the initial values supplied from the client */
    assert(tls->key_schedule == NULL);
    tls->key_schedule = key_schedule_new(ch.cipher_suite->hash, ptls_iovec_init(NULL, 0));
    key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0));
    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    /* send ServerHello */
    buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_SERVER_HELLO, {
        buffer_push16(sendbuf, PTLS_PROTOCOL_VERSION_DRAFT16);
        if ((ret = ptls_buffer_reserve(sendbuf, PTLS_HELLO_RANDOM_SIZE)) != 0)
            goto Exit;
        tls->ctx->crypto->random_bytes(sendbuf->base + sendbuf->off, PTLS_HELLO_RANDOM_SIZE);
        sendbuf->off += PTLS_HELLO_RANDOM_SIZE;
        buffer_push16(sendbuf, ch.cipher_suite->id);
        buffer_push_block(sendbuf, 2, {
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_KEY_SHARE, {
                buffer_push16(sendbuf, ch.key_share.algorithm->id);
                buffer_push_block(sendbuf, 2, { buffer_pushv(sendbuf, pubkey.base, pubkey.len); });
            });
            buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {});
        });
    });

    /* create protection contexts for the handshake */
    key_schedule_extract(tls->key_schedule, ecdh_secret);
    if ((ret = setup_protection_context(&tls->protection_ctx.send, tls->key_schedule, "server handshake traffic secret",
                                        ch.cipher_suite->aead, 1, "handshake key expansion")) != 0)
        goto Exit;
    if ((ret = setup_protection_context(&tls->protection_ctx.recv, tls->key_schedule, "client handshake traffic secret",
                                        ch.cipher_suite->aead, 0, "handshake key expansion")) != 0)
        goto Exit;

    /* send EncryptedExtensions */
    buffer_encrypt(sendbuf, tls->protection_ctx.send.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS, {
            buffer_push_block(sendbuf, 2, { buffer_push_extension(sendbuf, PTLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS, {}); });
        });
    });

    /* send Certificate */
    buffer_encrypt(sendbuf, tls->protection_ctx.send.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE, {
            buffer_push(sendbuf, 0);
            buffer_push_block(sendbuf, 3, {
                for (size_t i = 0; i != num_certs; ++i) {
                    buffer_push_block(sendbuf, 3, { buffer_pushv(sendbuf, certs[i].base, certs[i].len); });
                }
            });
        });
    });

#define CONTEXT_STRING "TLS 1.3, server CertificateVerify"
    /* build and send CertificateVerify */
    buffer_encrypt(sendbuf, tls->protection_ctx.send.aead, {
        buffer_push_handshake(sendbuf, tls->key_schedule, PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY, {
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
            buffer_push16(sendbuf, sign_algorithm);
            buffer_push_block(sendbuf, 2, { buffer_pushv(sendbuf, sign.base, sign.len); });
            free(sign.base);
        });
    });
#undef CONTEXT_STRING

    if ((ret = key_schedule_extract(tls->key_schedule, ptls_iovec_init(NULL, 0))) != 0)
        return ret;

    send_finished(tls, sendbuf);

    if ((ret = setup_protection_context(&tls->protection_ctx.send, tls->key_schedule, "server application traffic secret",
                                        tls->protection_ctx.send.aead->algo, 1, "application data key expansion")) != 0)
        return ret;

    tls->state = PTLS_STATE_SERVER_EXPECT_FINISHED;
    ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

Exit:
    free(pubkey.base);
    free(ecdh_secret.base);
    ptls_clear_memory(finished_key, sizeof(finished_key));
    dispose_protection_context(&tls->protection_ctx.send); /* dispose now that we have sent all handshake traffic */
    return ret;
}

static int server_handle_finished(ptls_t *tls, ptls_iovec_t message)
{
    int ret;

    if ((ret = verify_finished(tls, message)) != 0)
        return ret;

    if ((ret = setup_protection_context(&tls->protection_ctx.recv, tls->key_schedule, "client application traffic secret",
                                        tls->protection_ctx.recv.aead->algo, 0, "application data key expansion")) != 0)
        return ret;

    key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    tls->state = PTLS_STATE_POST_HANDSHAKE;
    return 0;
}

static int parse_record_header(struct st_ptls_record_t *rec, const uint8_t *src)
{
    rec->type = src[0];
    rec->version = ntoh16(src + 1);
    rec->length = ntoh16(src + 3);

    if (rec->length > (rec->type == PTLS_CONTENT_TYPE_APPDATA ? PTLS_MAX_ENCRYPTED_RECORD_SIZE : PTLS_MAX_PLAINTEXT_RECORD_SIZE))
        return PTLS_ALERT_DECODE_ERROR;

    return 0;
}

static int parse_record(ptls_t *tls, struct st_ptls_record_t *rec, const uint8_t *src, size_t *len)
{
    int ret;

    if (tls->recvbuf.rec.base == NULL && *len >= 5) {
        /* fast path */
        if ((ret = parse_record_header(rec, src)) != 0)
            return ret;
        if (5 + rec->length <= *len) {
            rec->fragment = src + 5;
            *len = rec->length + 5;
            return 0;
        }
    }

    /* slow path */
    const uint8_t *end = src + *len;
    *rec = (struct st_ptls_record_t){0};

    if (tls->recvbuf.rec.base == NULL) {
        ptls_buffer_init(&tls->recvbuf.rec, "", 0);
        if ((ret = ptls_buffer_reserve(&tls->recvbuf.rec, 5)) != 0)
            return ret;
    }

    /* fill and parse the header */
    while (tls->recvbuf.rec.off < 5) {
        if (src == end)
            return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
        tls->recvbuf.rec.base[tls->recvbuf.rec.off++] = *src++;
    }
    if ((ret = parse_record_header(rec, tls->recvbuf.rec.base)) != 0)
        return ret;

    /* fill the fragment */
    size_t addlen = rec->length + 5 - tls->recvbuf.rec.off;
    if (addlen != 0) {
        if ((ret = ptls_buffer_reserve(&tls->recvbuf.rec, addlen)) != 0)
            return ret;
        if (addlen > end - src)
            addlen = end - src;
        memcpy(tls->recvbuf.rec.base + tls->recvbuf.rec.off, src, addlen);
        tls->recvbuf.rec.off += addlen;
        src += addlen;
    }

    /* set rec->fragment if a complete record has been parsed */
    if (tls->recvbuf.rec.off == rec->length + 5) {
        rec->fragment = tls->recvbuf.rec.base + 5;
        ret = 0;
    } else {
        ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
    }

    *len = end - src;
    return 0;
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
    ptls_buffer_dispose(&tls->recvbuf.rec);
    ptls_buffer_dispose(&tls->recvbuf.mess);
    if (tls->key_schedule != NULL)
        key_schedule_free(tls->key_schedule);
    free(tls->client.server_name);
    free(tls);
}

ptls_context_t *ptls_get_context(ptls_t *tls)
{
    return tls->ctx;
}

static int test_handshake_message(const uint8_t *src, size_t src_len)
{
    uint32_t body_len;

    if (src_len < 4)
        return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;

    body_len = ntoh24(src + 1);
    if (body_len > src_len - 4) {
        return PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
    } else if (body_len < src_len - 4) {
        return PTLS_ALERT_DECODE_ERROR;
    }

    return 0;
}

static int handle_handshake_message(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_iovec_t message)
{
    uint8_t type = message.base[0];
    int ret;

    if (tls->key_schedule != NULL && type != PTLS_HANDSHAKE_TYPE_FINISHED)
        key_schedule_update_hash(tls->key_schedule, message.base, message.len);

    switch (tls->state) {
    case PTLS_STATE_CLIENT_EXPECT_SERVER_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_SERVER_HELLO) {
            ret = client_handle_hello(tls, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_ENCRYPTED_EXTENSIONS:
        if (type == PTLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS) {
            /* TODO implement */
            tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE;
            ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE) {
            /* TODO implement */
            tls->state = PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY;
            ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_CERTIFICATE_VERIFY:
        if (type == PTLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY) {
            /* TODO implement */
            tls->state = PTLS_STATE_CLIENT_EXPECT_FINISHED;
            ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_CLIENT_EXPECT_FINISHED:
        if (type == PTLS_HANDSHAKE_TYPE_FINISHED) {
            ret = client_handle_finished(tls, sendbuf, message);
        } else {
            ret = PTLS_ALERT_UNEXPECTED_MESSAGE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_CLIENT_HELLO:
        if (type == PTLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
            ret = server_handle_hello(tls, sendbuf, message);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        break;
    case PTLS_STATE_SERVER_EXPECT_FINISHED:
        if (type == PTLS_HANDSHAKE_TYPE_FINISHED) {
            ret = server_handle_finished(tls, message);
        } else {
            ret = PTLS_ALERT_HANDSHAKE_FAILURE;
        }
        break;
    default:
        assert(!"unexpected state");
        break;
    }

    return ret;
}

static int ptls_handle_input(ptls_t *tls, ptls_buffer_t *sendbuf, ptls_buffer_t *decryptbuf, const void *input, size_t *inlen)
{
    struct st_ptls_record_t rec;
    int ret;

    /* extract the record */
    if ((ret = parse_record(tls, &rec, input, inlen)) != 0)
        return ret;
    assert(rec.fragment != NULL);

    /* decrypt the record */
    if (tls->protection_ctx.recv.aead != NULL) {
        if (rec.type != PTLS_CONTENT_TYPE_APPDATA)
            return PTLS_ALERT_HANDSHAKE_FAILURE;
        if ((ret = ptls_buffer_reserve(decryptbuf, 5 + rec.length)) != 0)
            return ret;
        if ((ret = ptls_aead_transform(tls->protection_ctx.recv.aead, decryptbuf->base + decryptbuf->off, &rec.length, rec.fragment,
                                       rec.length, 0)) != 0)
            return ret;
        rec.fragment = decryptbuf->base + decryptbuf->off;
        /* skip padding */
        for (; rec.length != 0; --rec.length)
            if (rec.fragment[rec.length - 1] != 0)
                break;
        if (rec.length == 0)
            return PTLS_ALERT_UNEXPECTED_MESSAGE;
        rec.type = rec.fragment[--rec.length];
    }

    if (tls->recvbuf.mess.base != NULL || rec.type == PTLS_CONTENT_TYPE_HANDSHAKE) {

        /* handshake */
        ptls_iovec_t message = {NULL};
        if (rec.type != PTLS_CONTENT_TYPE_HANDSHAKE)
            return PTLS_ALERT_DECODE_ERROR;

        /* handle the record directly, or buffer the message split into multiple records */
        if (tls->recvbuf.mess.base == NULL && test_handshake_message(rec.fragment, rec.length) == 0) {
            message = ptls_iovec_init(rec.fragment, rec.length);
        } else {
            if ((ret = ptls_buffer_reserve(&tls->recvbuf.mess, rec.length)) != 0)
                return ret;
            memcpy(tls->recvbuf.mess.base + tls->recvbuf.mess.off, rec.fragment, rec.length);
            tls->recvbuf.mess.off += rec.length;
            if ((ret = test_handshake_message(tls->recvbuf.mess.base, tls->recvbuf.mess.off)) == 0)
                message = ptls_iovec_init(tls->recvbuf.mess.base, tls->recvbuf.mess.off);
        }

        /* handle the complete message, if available */
        if (message.base != NULL) {
            ret = handle_handshake_message(tls, sendbuf, message);
            ptls_buffer_dispose(&tls->recvbuf.mess);
        }

    } else {

        /* handling of an alert or an application record */
        switch (rec.type) {
        case PTLS_CONTENT_TYPE_APPDATA:
            decryptbuf->off += rec.length;
            ret = 0;
            break;
        case PTLS_CONTENT_TYPE_ALERT:
            assert(!"FIXME");
            break;
        default:
            assert(!"FIXME");
            break;
        }
    }

    /* cleanup */
    ptls_buffer_dispose(&tls->recvbuf.rec);

    return ret;
}

int ptls_handshake(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t *inlen)
{
    assert(tls->state != PTLS_STATE_POST_HANDSHAKE);

    /* special handling for initiating the handshake */
    if (tls->state == PTLS_STATE_CLIENT_HANDSHAKE_START) {
        assert(input == NULL || *inlen == 0);
        return send_client_hello(tls, sendbuf);
    }

    const uint8_t *src = input, *src_end = src + *inlen;
    int ret = PTLS_ERROR_HANDSHAKE_IN_PROGRESS;
    ptls_buffer_t decryptbuf;
    uint8_t decryptbuf_small[256];

    ptls_buffer_init(&decryptbuf, decryptbuf_small, sizeof(decryptbuf_small));

    /* perform handhake until completion or until all the input has been swallowed */
    while (ret == PTLS_ERROR_HANDSHAKE_IN_PROGRESS && src != src_end) {
        size_t consumed = src_end - src;
        ret = ptls_handle_input(tls, sendbuf, &decryptbuf, src, &consumed);
        src += consumed;
        assert(decryptbuf.off == 0);
    }
    if (sendbuf->base == NULL || decryptbuf.base == NULL)
        ret = PTLS_ERROR_NO_MEMORY;

    ptls_buffer_dispose(&decryptbuf);

    if (!(ret == 0 || ret == PTLS_ERROR_HANDSHAKE_IN_PROGRESS)) {
        /* send alert immediately */
        ret = send_alert(tls, sendbuf, PTLS_ALERT_LEVEL_FATAL, -(PTLS_ERROR_IS_ALERT(ret) ? ret : PTLS_ALERT_INTERNAL_ERROR));
    }

    *inlen -= src_end - src;
    return ret;
}

int ptls_receive(ptls_t *tls, ptls_buffer_t *decryptbuf, const void *input, size_t *inlen)
{
    int ret;

    assert(tls->state >= PTLS_STATE_SERVER_EXPECT_FINISHED);

    ret = ptls_handle_input(tls, NULL, decryptbuf, input, inlen);
    if (decryptbuf->base == NULL)
        ret = PTLS_ERROR_NO_MEMORY;

    if (ret == PTLS_ERROR_HANDSHAKE_IN_PROGRESS) {
        ret = 0;
    } else {
        /* TODO send alert */
    }

    return ret;
}

int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *_input, size_t inlen)
{
    const uint8_t *input = (const uint8_t *)_input;
    size_t pt_size, enc_size;
    int ret = 0;

    assert(tls->state >= PTLS_STATE_SERVER_EXPECT_FINISHED);

    for (; inlen != 0; input += pt_size, inlen -= pt_size) {
        pt_size = inlen;
        if (pt_size > PTLS_MAX_PLAINTEXT_RECORD_SIZE)
            pt_size = PTLS_MAX_PLAINTEXT_RECORD_SIZE;
        buffer_push_record(sendbuf, PTLS_CONTENT_TYPE_APPDATA, {
            if ((ret = ptls_buffer_reserve(sendbuf, pt_size + 256)) != 0)
                break;
            if ((ret = ptls_aead_transform(tls->protection_ctx.send.aead, sendbuf->base + sendbuf->off, &enc_size, input, pt_size,
                                           PTLS_CONTENT_TYPE_APPDATA)) != 0)
                break;
            sendbuf->off += enc_size;
        });
    }

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

int ptls_aead_transform(ptls_aead_context_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen,
                        uint8_t enc_content_type)
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

    if ((ret = ctx->do_transform(ctx, output, outlen, input, inlen, iv, enc_content_type)) != 0)
        return ret;

    ++ctx->seq;
    return 0;
}

static void clear_memory(void *p, size_t len)
{
    memset(p, 0, len);
}

void (*volatile ptls_clear_memory)(void *p, size_t len) = clear_memory;
