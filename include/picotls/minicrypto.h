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
#ifndef picotls_minicrypto_h
#define picotls_minicrypto_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "picotls.h"

/* defaults */
#ifndef PTLS_USE_OPENSSL
#define PTLS_USE_OPENSSL                    0
#endif
#ifndef PTLS_HAVE_AEGIS
#define PTLS_HAVE_AEGIS                     0
#endif

/* minicrypto */
extern ptls_hash_algorithm_t ptls_minicrypto_sha256, ptls_minicrypto_sha384, ptls_minicrypto_sha5;
extern ptls_cipher_algorithm_t ptls_minicrypto_aes128ecb, ptls_minicrypto_aes256ecb,
                               ptls_minicrypto_aes128ctr, ptls_minicrypto_aes256ctr,
                               ptls_minicrypto_chacha20;
extern ptls_aead_algorithm_t ptls_minicrypto_aes128gcm, ptls_minicrypto_aes256gcm,
                             ptls_minicrypto_chacha20poly1305;
extern ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256, ptls_minicrypto_aes256gcmsha384,
                           ptls_minicrypto_chacha20poly1305sha256;
extern ptls_key_exchange_algorithm_t ptls_minicrypto_secp256r1,
                                     ptls_minicrypto_x25519;

void ptls_minicrypto_random_bytes(void *buf, size_t len);

/* convenience interface */
#if PTLS_USE_OPENSSL
#include "openssl.h"

#define ptls_crypto_sha256                  ptls_openssl_sha256
#define ptls_crypto_sha384                  ptls_openssl_sha384
#define ptls_crypto_sha512                  ptls_openssl_sha512

#define ptls_crypto_aes128ecb               ptls_openssl_aes128ecb
#define ptls_crypto_aes128ctr               ptls_openssl_aes128ctr
#define ptls_crypto_aes128gcm               ptls_openssl_aes128gcm
#define ptls_crypto_aes128gcmsha256         ptls_openssl_aes128gcmsha256

#define ptls_crypto_aes256ecb               ptls_openssl_aes256ecb
#define ptls_crypto_aes256ctr               ptls_openssl_aes256ctr
#define ptls_crypto_aes256gcm               ptls_openssl_aes256gcm
#define ptls_crypto_aes256gcmsha384         ptls_openssl_aes256gcmsha384

#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
#define PTLS_CRYPTO_HAVE_CHACHA20_POLY1305  1
#define ptls_crypto_chacha20                ptls_openssl_chacha20
#define ptls_crypto_chacha20poly1305        ptls_openssl_chacha20poly1305
#define ptls_crypto_chacha20poly1305sha256  ptls_openssl_chacha20poly1305sha256
#endif

#if PTLS_HAVE_AEGIS
#define PTLS_CRYPTO_HAVE_AEGIS              1
#define ptls_crypto_aegis128l               ptls_openssl_aegis128l
#define ptls_crypto_aegis256                ptls_openssl_aegis256
#define ptls_crypto_aegis128lsha256         ptls_openssl_aegis128lsha256
#define ptls_crypto_aegis256sha512          ptls_openssl_aegis256sha512
#endif

#define ptls_crypto_secp256r1               ptls_openssl_secp256r1
#if PTLS_OPENSSL_HAVE_SECP384R1
#define PTLS_CRYPTO_HAVE_SECP384R1          1
#define ptls_crypto_secp384r1               ptls_openssl_secp384r1
#endif

#if PTLS_OPENSSL_HAVE_SECP521R1
#define PTLS_CRYPTO_HAVE_SECP521R1          1
#define ptls_crypto_secp521r1               ptls_openssl_secp521r1
#endif

#if PTLS_OPENSSL_HAVE_X25519
#define PTLS_CRYPTO_HAVE_X25519             1
#define ptls_crypto_x25519                  ptls_openssl_x25519
#endif

#if PTLS_OPENSSL_HAVE_X25519MLKEM768
#define PTLS_CRYPTO_HAVE_X25519MLKEM768     1
extern ptls_key_exchange_algorithm_t ptls_openssl_x25519mlkem768;
#define ptls_openssl_x25519mlkem768         ptls_crypto_x25519mlkem768
#endif

#define ptls_crypto_random_bytes            ptls_openssl_random_bytes

/* crypto available */
void ptls_openssl_init_cipher_suites(ptls_context_t *ptls_ctx);
void ptls_openssl_init_key_exchanges(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_cipher_suites      ptls_openssl_init_cipher_suites
#define ptls_crypto_init_key_exchanges      ptls_openssl_init_key_exchanges

/* init sign */
int ptls_openssl_init_sign_file(ptls_context_t *ptls_ctx, const char *privatekey_file, const char *certificate_file);
int ptls_openssl_init_sign_der(ptls_context_t *ptls_ctx, const ptls_iovec_t *privatekey, const ptls_iovec_t certificate[], size_t certificate_length);
void ptls_openssl_dispose_sign(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_sign_file          ptls_openssl_init_sign_file
#define ptls_crypto_init_sign_der           ptls_openssl_init_sign_der
#define ptls_crypto_dispose_sign            ptls_openssl_dispose_sign

/* init verify */
int ptls_openssl_init_verify_file(ptls_context_t *ptls_ctx, const char *truststore_file);
int ptls_openssl_init_verify_der(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length);
void ptls_openssl_dispose_verify(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_verify_file        ptls_openssl_init_verify_file
#define ptls_crypto_init_verify_der         ptls_openssl_init_verify_der
#define ptls_crypto_dispose_verify          ptls_openssl_dispose_verify

#else

#define ptls_crypto_sha256                  ptls_minicrypto_sha256
#define ptls_crypto_sha384                  ptls_minicrypto_sha384
#define ptls_crypto_sha512                  ptls_minicrypto_sha512

#define ptls_crypto_aes128ecb               ptls_minicrypto_aes128ecb
#define ptls_crypto_aes128ctr               ptls_minicrypto_aes128ctr
#define ptls_crypto_aes128gcm               ptls_minicrypto_aes128gcm
#define ptls_crypto_aes128gcmsha256         ptls_minicrypto_aes128gcmsha256

#define ptls_crypto_aes256ecb               ptls_minicrypto_aes256ecb
#define ptls_crypto_aes256ctr               ptls_minicrypto_aes256ctr
#define ptls_crypto_aes256gcm               ptls_minicrypto_aes256gcm
#define ptls_crypto_aes256gcmsha384         ptls_minicrypto_aes256gcmsha384

#define PTLS_CRYPTO_HAVE_CHACHA20_POLY1305  1
#define ptls_crypto_chacha20                ptls_minicrypto_chacha20
#define ptls_crypto_chacha20poly1305        ptls_minicrypto_chacha20poly1305
#define ptls_crypto_chacha20poly1305sha256  ptls_minicrypto_chacha20poly1305sha256

#if PTLS_HAVE_AEGIS
extern ptls_aead_algorithm_t ptls_minicrypto_aegis128l,
                             ptls_minicrypto_aegis256;
extern ptls_cipher_suite_t ptls_minicrypto_aegis128lsha256,
                           ptls_minicrypto_aegis256sha512;
#define PTLS_CRYPTO_HAVE_AEGIS              1
#define ptls_crypto_aegis128l               ptls_minicrypto_aegis128l
#define ptls_crypto_aegis256                ptls_minicrypto_aegis256
#define ptls_crypto_aegis128lsha256         ptls_minicrypto_aegis128lsha256
#define ptls_crypto_aegis256sha512          ptls_minicrypto_aegis256sha512
#endif

#define ptls_crypto_secp256r1               ptls_minicrypto_secp256r1
/*
#define PTLS_CRYPTO_HAVE_SECP384R1          1
#define ptls_crypto_secp384r1               ptls_minicrypto_secp384r1
#define PTLS_CRYPTO_HAVE_SECP521R1          1
#define ptls_crypto_secp521r1               ptls_minicrypto_secp521r1
*/

#define PTLS_CRYPTO_HAVE_X25519             1
#define ptls_crypto_x25519                  ptls_minicrypto_x25519

#define ptls_crypto_random_bytes            ptls_minicrypto_random_bytes

/* crypto available */
void ptls_minicrypto_init_cipher_suites(ptls_context_t *ptls_ctx);
void ptls_minicrypto_init_key_exchanges(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_cipher_suites      ptls_minicrypto_init_cipher_suites
#define ptls_crypto_init_key_exchanges      ptls_minicrypto_init_key_exchanges

/* init sign */
int ptls_minicrypto_init_sign_file(ptls_context_t *ptls_ctx, const char *privatekey_file, const char *certificate_file);
int ptls_minicrypto_init_sign_der(ptls_context_t *ptls_ctx, const ptls_iovec_t *privatekey, const ptls_iovec_t certificate[], size_t certificate_length);
void ptls_minicrypto_dispose_sign(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_sign_file          ptls_minicrypto_init_sign_file
#define ptls_crypto_init_sign_der           ptls_minicrypto_init_sign_der
#define ptls_crypto_dispose_sign            ptls_minicrypto_dispose_sign

/* init verify */
int ptls_minicrypto_init_verify_file(ptls_context_t *ptls_ctx, const char *truststore_file);
int ptls_minicrypto_init_verify_der(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length);
void ptls_minicrypto_dispose_verify(ptls_context_t *ptls_ctx);
#define ptls_crypto_init_verify_file        ptls_minicrypto_init_verify_file
#define ptls_crypto_init_verify_der         ptls_minicrypto_init_verify_der
#define ptls_crypto_dispose_verify          ptls_minicrypto_dispose_verify

#endif

#ifdef __cplusplus
}
#endif

#endif
