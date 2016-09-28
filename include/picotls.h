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

#include <inttypes.h>

#define PTLS_MAX_SECRET_SIZE 32
#define PTLS_MAX_DIGEST_SIZE 64

/* cipher-suites */
#define PTLS_CIPHER_SUITE_AES_128_GCM_SHA256 0x1301
#define PTLS_CIPHER_SUITE_AES_256_GCM_SHA384 0x1302
#define PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256 0x1303

/* negotiated_groups */
#define PTLS_GROUP_SECP256R1 23
#define PTLS_GROUP_X25519 29

/* signature algorithms */
#define PTLS_SIGNATURE_RSA_PKCS1_SHA256 0x0401
#define PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 0x0403
#define PTLS_SIGNATURE_RSA_PSS_SHA256 0x0804

/* alerts & errors */
#define PTLS_ALERT_HANDSHAKE_FAILURE -40
#define PTLS_ALERT_DECODE_ERROR -50
#define PTLS_ALERT_MISSING_EXTENSION -109
#define PTLS_ALERT_UNRECOGNIZED_NAME -112
#define PTLS_ERROR_NO_MEMORY -100001
#define PTLS_ERROR_INCOMPLETE_HANDSHAKE -100002
#define PTLS_ERROR_LIBRARY -100003

typedef struct st_ptls_t ptls_t;

typedef struct st_ptls_iovec_t {
    uint8_t *base;
    size_t len;
} ptls_iovec_t;

typedef struct st_ptls_crypto_t ptls_crypto_t;

typedef struct st_ptls_context_t {
    ptls_crypto_t *crypto;
    struct {
        int (*client_hello)(ptls_t *tls, uint16_t *sign_algorithm,
                            int (**signer)(void *sign_ctx, ptls_iovec_t *output, ptls_iovec_t input), void *signer_data,
                            ptls_iovec_t **certs, size_t *num_certs, ptls_iovec_t server_name, const uint16_t *signature_algorithms,
                            size_t num_signature_algorithms);
    } callbacks;
} ptls_context_t;

typedef struct st_ptls_key_exchange_algorithm_t {
    uint16_t id;
    int (*key_exchange)(ptls_iovec_t *pubkey, ptls_iovec_t *secret, ptls_iovec_t peerkey);
} ptls_key_exchange_algorithm_t;

typedef struct st_ptls_aead_context_t {
    void (*destroy)(struct st_ptls_aead_context_t *ctx);
    size_t (*transform)(struct st_ptls_aead_context_t *ctx, void *output, const void *input, size_t inlen);
    uint64_t nonce;
} ptls_aead_context_t;

typedef struct st_ptls_aead_algorithm_t {
    size_t key_size;
    size_t block_size;
    ptls_aead_context_t *(*create)(const uint8_t *key);
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

typedef struct st_ptls_crypto_t {
    void (*random_bytes)(void *buf, size_t len);
    /**
     * list of supported key-exchange algorithms terminated by .id == UINT16_MAX
     */
    ptls_key_exchange_algorithm_t *key_exchanges;
    /**
     * list of supported cipher-suites terminated by .id == UINT16_MAX
     */
    ptls_cipher_suite_t *cipher_suites;
} ptls_crypto_t;

/**
 *
 */
ptls_t *ptls_new(ptls_context_t *ctx);
/**
 *
 */
void ptls_free(ptls_t *tls);
/**
 *
 */
ptls_context_t *ptls_get_context(ptls_t *tls);
/**
 *
 */
int ptls_handshake(ptls_t *tls, const void *input, size_t *inlen, void *output, size_t *outlen);
/**
 *
 */
int ptls_decrypt(ptls_t *tls, const void *encrypted, size_t *enclen, void *dst, size_t *dstlen);
/**
 *
 */
int ptls_enrypt(ptls_t *tls, const void *src, size_t *srclen, void *encrypted, size_t *enclen);
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
 * clears memory
 */
extern void (*volatile ptls_clear_memory)(void *p, size_t len);
/**
 *
 */
static ptls_iovec_t ptls_iovec_init(const void *p, size_t len);

/* inline functions */

static inline ptls_iovec_t ptls_iovec_init(const void *p, size_t len)
{
    return (ptls_iovec_t){(uint8_t *)p, len};
}

#endif
