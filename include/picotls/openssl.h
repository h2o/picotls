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
#ifndef picotls_openssl_h
#define picotls_openssl_h

#include <openssl/evp.h>
#include <openssl/x509.h>
#include "picotls.h"

extern ptls_key_exchange_algorithm_t ptls_openssl_secp256r1;
extern ptls_key_exchange_algorithm_t *ptls_openssl_key_exchanges[];
extern ptls_aead_algorithm_t ptls_openssl_aes128gcm;
extern ptls_hash_algorithm_t ptls_openssl_sha256;
extern ptls_cipher_suite_t ptls_openssl_aes128gcmsha256;
extern ptls_cipher_suite_t *ptls_openssl_cipher_suites[];
extern ptls_crypto_t ptls_openssl_crypto;

typedef struct st_ptls_openssl_t ptls_openssl_t;

ptls_openssl_t *ptls_openssl_new(void);
void ptls_openssl_free(ptls_openssl_t *ctx);
ptls_certificate_context_t *ptls_openssl_get_certificate_context(ptls_openssl_t *ctx);
int ptls_openssl_register_server(ptls_openssl_t *ctx, const char *server_name, EVP_PKEY *key, STACK_OF(X509) * certs);
int ptls_openssl_set_certificate_store(ptls_openssl_t *ctx, X509_STORE *store);

#endif
