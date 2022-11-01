/*
 * Copyright (c) 2022 Fastly, Kazuho Oku
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
#ifndef picotls_hpke_h
#define picotls_hpke_h

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "../picotls.h"

#define PTLS_HPKE_MODE_BASE 0
#define PTLS_HPKE_MODE_PSK 1
#define PTLS_HPKE_MODE_AUTH 2
#define PTLS_HPKE_MODE_AUTH_PSK 3

#define PTLS_HPKE_KEM_P256_SHA256 16
#define PTLS_HPKE_KEM_P384_SHA384 17
#define PTLS_HPKE_KEM_X25519_SHA256 32

#define PTLS_HPKE_HKDF_SHA256 1
#define PTLS_HPKE_HKDF_SHA384 2
#define PTLS_HPKE_HKDF_SHA512 3

#define PTLS_HPKE_AEAD_AES_128_GCM 1
#define PTLS_HPKE_AEAD_AES_256_GCM 2
#define PTLS_HPKE_AEAD_CHACHA20POLY1305 3

typedef const struct st_ptls_hpke_kem_t {
    uint16_t id;
    ptls_key_exchange_algorithm_t *keyex;
    ptls_hash_algorithm_t *hash;
} ptls_hpke_kem_t;

/**
 * SetupBaseS function of RFC 9180. Given `kem`, `algo`, `info`, and receiver's public key, returns an ephemeral public key and an
 * AEAD context used for encrypting data.
 */
int ptls_hpke_setup_base_s(ptls_hpke_kem_t *kem, ptls_aead_algorithm_t *algo, ptls_iovec_t *pk_s, ptls_aead_context_t **ctx,
                           ptls_iovec_t pk_r, ptls_iovec_t info);
/**
 * SetupBaseR function of RFC 9180. Given `kem`, `algo`, `info`, receiver's private key (`keyex`), and the esnder's public key,
 * returns the AEAD context to be used for decrypting data.
 */
int ptls_hpke_setup_base_r(ptls_hpke_kem_t *kem, ptls_aead_algorithm_t *algo, ptls_key_exchange_context_t *keyex,
                           ptls_aead_context_t **ctx, ptls_iovec_t pk_s, ptls_iovec_t info);

#ifdef __cplusplus
}
#endif

#endif
