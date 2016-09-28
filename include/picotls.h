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

typedef struct st_ptls_context_t {
    struct {
        int (*server_name)(ptls_t *tls, X509 **cert, STACK_OF(X509) * *extra_certs);
    } callbacks;
} ptls_context_t;

typedef struct st_ptls_aead_context_t {
    /**
     *
     */
    uint64_t nonce;
    /**
     * callback used to encrypt a record
     */
    size_t (*transform)(struct st_ptls_aead_context_t *ctx, uint8_t *output, const uint8_t *input, size_t inlen);
} ptls_aead_context_t;

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

#endif
