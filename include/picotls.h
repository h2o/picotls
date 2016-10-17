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
#ifndef picotls_h
#define picotls_h

#include <assert.h>
#include <inttypes.h>

#define PTLS_MAX_SECRET_SIZE 32
#define PTLS_MAX_IV_SIZE 16
#define PTLS_MAX_DIGEST_SIZE 64

/* cipher-suites */
#define PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define PTLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* negotiated_groups */
#define PTLS_GROUP_SECP256R1 23
#define PTLS_GROUP_X25519 29

/* signature algorithms */
#define PTLS_SIGNATURE_RSA_PKCS1_SHA1 0x0201
#define PTLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define PTLS_SIGNATURE_RSA_PSS_SHA256 0x0804

/* alerts & errors */
#define PTLS_ALERT_UNEXPECTED_MESSAGE 10
#define PTLS_ALERT_BAD_RECORD_MAC 20
#define PTLS_ALERT_HANDSHAKE_FAILURE 40
#define PTLS_ALERT_BAD_CERTIFICATE 42
#define PTLS_ALERT_CERTIFICATE_REVOKED 44
#define PTLS_ALERT_CERTIFICATE_EXPIRED 45
#define PTLS_ALERT_CERTIFICATE_UNKNOWN 46
#define PTLS_ALERT_ILLEGAL_PARAMETER 47
#define PTLS_ALERT_DECODE_ERROR 50
#define PTLS_ALERT_DECRYPT_ERROR 51
#define PTLS_ALERT_INTERNAL_ERROR 80
#define PTLS_ALERT_MISSING_EXTENSION 109
#define PTLS_ALERT_UNRECOGNIZED_NAME 112
#define PTLS_ERROR_NO_MEMORY -1
#define PTLS_ERROR_HANDSHAKE_IN_PROGRESS -2
#define PTLS_ERROR_LIBRARY -3
#define PTLS_ERROR_INCOMPATIBLE_KEY -4

#define PTLS_ERROR_IS_ALERT(e) ((e) > 0)

typedef struct st_ptls_t ptls_t;

typedef struct st_ptls_iovec_t {
    uint8_t *base;
    size_t len;
} ptls_iovec_t;

typedef struct st_ptls_buffer_t {
    uint8_t *base;
    size_t capacity;
    size_t off;
    int is_allocated;
} ptls_buffer_t;

typedef struct st_ptls_crypto_t ptls_crypto_t;

typedef struct st_ptls_context_t {
    ptls_crypto_t *crypto;
    struct {
        int (*client_hello)(ptls_t *tls, uint16_t *sign_algorithm,
                            int (**signer)(void *sign_ctx, ptls_iovec_t *output, ptls_iovec_t input), void **signer_data,
                            ptls_iovec_t **certs, size_t *num_certs, ptls_iovec_t server_name, const uint16_t *signature_algorithms,
                            size_t num_signature_algorithms);
        int (*certificate)(ptls_t *tls, int (**verifier)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature),
                           void **verifer_data, ptls_iovec_t *certs, size_t num_certs);
    } callbacks;
} ptls_context_t;

typedef struct st_ptls_key_exchange_context_t {
    int (*on_exchange)(struct st_ptls_key_exchange_context_t *keyex, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_context_t;

typedef struct st_ptls_key_exchange_algorithm_t {
    uint16_t id;
    int (*create)(ptls_key_exchange_context_t **ctx, ptls_iovec_t *pubkey);
    int (*exchange)(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_algorithm_t;

typedef struct st_ptls_aead_context_t {
    void *crypto_ctx;
    void (*dispose_crypto)(struct st_ptls_aead_context_t *ctx);
    int (*do_transform)(struct st_ptls_aead_context_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen,
                        const void *iv, uint8_t enc_content_type);
    /* following fields must not be altered by the crypto binding */
    struct st_ptls_aead_algorithm_t *algo;
    uint64_t seq;
    uint8_t static_iv[1];
} ptls_aead_context_t;

typedef struct st_ptls_aead_algorithm_t {
    size_t key_size;
    size_t iv_size;
    int (*setup_crypto)(ptls_aead_context_t *ctx, int is_enc, const void *key);
} ptls_aead_algorithm_t;

typedef enum en_ptls_hash_final_mode_t {
    PTLS_HASH_FINAL_MODE_FREE = 0,
    PTLS_HASH_FINAL_MODE_RESET = 1,
    PTLS_HASH_FINAL_MODE_SNAPSHOT = 2
} ptls_hash_final_mode_t;

typedef struct st_ptls_hash_context_t {
    void (*update)(struct st_ptls_hash_context_t *ctx, const void *src, size_t len);
    void (* final)(struct st_ptls_hash_context_t *ctx, void *md, ptls_hash_final_mode_t mode);
} ptls_hash_context_t;

typedef struct st_ptls_hash_algorithm_t {
    size_t block_size;
    size_t digest_size;
    ptls_hash_context_t *(*create)(void);
} ptls_hash_algorithm_t;

typedef struct st_ptls_cipher_suite_t {
    uint16_t id;
    ptls_aead_algorithm_t *aead;
    ptls_hash_algorithm_t *hash;
} ptls_cipher_suite_t;

struct st_ptls_crypto_t {
    void (*random_bytes)(void *buf, size_t len);
    /**
     * list of supported key-exchange algorithms terminated by .id == UINT16_MAX
     */
    ptls_key_exchange_algorithm_t *key_exchanges;
    /**
     * list of supported cipher-suites terminated by .id == UINT16_MAX
     */
    ptls_cipher_suite_t *cipher_suites;
};

/**
 *
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);
/**
 *
 */
static void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size);
/**
 *
 */
static void ptls_buffer_dispose(struct st_ptls_buffer_t *buf);
/**
 *
 */
void ptls_buffer__release_memory(struct st_ptls_buffer_t *buf);
/**
 *
 */
int ptls_buffer_reserve(struct st_ptls_buffer_t *buf, size_t delta);

/**
 *
 */
ptls_t *ptls_new(ptls_context_t *ctx, const char *server_name);
/**
 *
 */
void ptls_free(ptls_t *tls);
/**
 *
 */
ptls_context_t *ptls_get_context(ptls_t *tls);
/**
 * proceeds with the handshake, optionally taking some input from peer
 */
int ptls_handshake(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t *inlen);
/**
 * decrypts the first record within given buffer
 */
int ptls_receive(ptls_t *tls, ptls_buffer_t *plaintextbuf, const void *input, size_t *len);
/**
 * encrypts given buffer into multiple TLS records
 */
int ptls_send(ptls_t *tls, ptls_buffer_t *sendbuf, const void *input, size_t inlen);
/**
 *
 */
ptls_hash_context_t *ptls_hmac_create(ptls_hash_algorithm_t *algo, const void *key, size_t key_size);
/**
 *
 */
int ptls_hkdf_extract(ptls_hash_algorithm_t *hash, void *output, ptls_iovec_t salt, ptls_iovec_t ikm);
/**
 *
 */
int ptls_hkdf_expand(ptls_hash_algorithm_t *hash, void *output, size_t outlen, ptls_iovec_t prk, ptls_iovec_t info);
/**
 *
 */
ptls_aead_context_t *ptls_aead_new(ptls_aead_algorithm_t *aead, ptls_hash_algorithm_t *hash, int is_enc, const void *secret,
                                   const char *label);
/**
 *
 */
void ptls_aead_free(ptls_aead_context_t *ctx);
/**
 *
 */
int ptls_aead_transform(ptls_aead_context_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen,
                        uint8_t enc_content_type);
/**
 * clears memory
 */
extern void (*volatile ptls_clear_memory)(void *p, size_t len);
/**
 *
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);

/* inline functions */

inline ptls_iovec_t ptls_iovec_init(const void *p, size_t len)
{
    return (ptls_iovec_t){(uint8_t *)p, len};
}

inline void ptls_buffer_init(ptls_buffer_t *buf, void *smallbuf, size_t smallbuf_size)
{
    assert(smallbuf != NULL);
    buf->base = smallbuf;
    buf->off = 0;
    buf->capacity = smallbuf_size;
    buf->is_allocated = 0;
}

inline void ptls_buffer_dispose(ptls_buffer_t *buf)
{
    ptls_buffer__release_memory(buf);
    *buf = (ptls_buffer_t){NULL};
}

#endif
