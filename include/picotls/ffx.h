/*
 * Copyright (c) 2019 Christian Huitema <huitema@huitema.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PTLS_FFX_H
#define PTLS_FFX_H

/*
 * Format preserving encryption using the FFX algorithm.
 *
 * We demonstrate here a simple encryption process derived
 * from the FFX algorithms, which is effectively a specific
 * mode of running a verified encryption code. The
 * algorithm is Feistel cipher in which the S-boxes are
 * defined by a symmetric encryption algorithm such as
 * AES or ChaCha20.
 * See "Ciphers with Arbitrary Finite Domains" by
 * John Black and Phillip Rogaway, 2001 --
 * http://web.cs.ucdavis.edu/~rogaway/papers/subset.pdf
 *
 * An instantiation of the algorithm is defined by a
 * series of parameters:
 *   - the context of the symmetric crypto algorithm,
 *   - key used for the symmetric algorithm,
 *   - number of rounds,
 *   - length of the block in bits
 *
 * We consider just two symmetric algorithms for now,
 * ChaCha20 and AES128CTR. In theory, any symmetric algorithm
 * operating on a 128 bit block would work, and crytographic
 * hashes producing at least 128 bits of output could also
 * be used. In practice, ChaCha20 and AES128 cover most of
 * the use cases.
 *
 * The implementation will produce a result for any block
 * length lower than 256, although values lower than 32 would
 * not be recommended.
 *
 * The block to be encrypted is passed as a byte array of size
 * (block_length + 7)/8. When the block_length is not a
 * multiple of 8, the algorithm guarantees that the extra bits
 * in the last byte are left untouched. For example, if the
 * block length is 39, the least significant bit of the
 * fifth byte will be copied from input to output.
 *
 * The number of rounds is left as a configuration parameter,
 * which is constrained to be even by our implementation. The
 * required number of passes varies with the application's
 * constraints. The practical minimum is 4 passes. Demanding
 * applications can use 8 passes, and the practical conservative
 * value is 10, as specified by NIST for the FF1 variant of
 * the same algorithm. This choice between 4, 8 or 10 is
 * based on "Luby-Rackoff: 7 Rounds are Enough
 * for 2^n(1-epsilon) Security" by Jacques Patarin, 2003 --
 * https://www.iacr.org/archive/crypto2003/27290510/27290510.pdf
 *
 * Encrypting short numbers, by nature, produces a codebook
 * of limited size. In many applications, the short number is
 * part of a larger object that is passed in clear text. In that
 * case, NIST recommends using as much as possible of that clear
 * text as an initialization vector, used as "tweak" in the
 * FFX algorithm. See:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf
 */

typedef struct st_ptls_ffx_context_t {
    ptls_cipher_context_t super;
    ptls_cipher_context_t *enc_ctx;
    int nb_rounds;
    size_t byte_length;
    size_t nb_left;
    size_t nb_right;
    uint8_t mask_last_byte;
    uint8_t tweaks[16];
} ptls_ffx_context_t;

int ptls_ffx_setup_crypto(ptls_cipher_context_t *_ctx, ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds,
                          size_t bit_length, const void *key);
void ptls_ffx_dispose(ptls_cipher_context_t *_ctx);
void ptls_ffx_encrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len);
void ptls_ffx_decrypt(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len);
void ptls_ffx_init(struct st_ptls_cipher_context_t *ctx, const void *iv);

ptls_cipher_context_t *ptls_ffx_new(ptls_cipher_algorithm_t *algo, int is_enc, int nb_rounds, size_t bit_length, const void *key);
void ptls_ffx_free(ptls_cipher_context_t *ctx);

#define PTLS_FFX_CIPHER_ALGO_NAME(base, bitlength, nbrounds) #base "-ffx-b" #bitlength "-r" #nbrounds

#define PTLS_FFX_CIPHER_ALGO(base, bitlength, nbrounds, keysize)                                                             \
    static int ptls_ffx_##base##_b##bitlength##_r##nbrounds##_setup(ptls_cipher_context_t *ctx, int is_enc, const void *key) \
    {                                                                                                                        \
        return ptls_ffx_setup_crypto(ctx, &base, is_enc, nbrounds, bitlength, key);                                          \
    }                                                                                                                        \
    ptls_cipher_algorithm_t ptls_ffx_##base##_b##bitlength##_r##nbrounds = {                                               \
        PTLS_FFX_CIPHER_ALGO_NAME(base, bitlength, nbrounds), keysize, 16, sizeof(ptls_ffx_context_t),                       \
         ptls_ffx_##base##_b##bitlength##_r##nbrounds##_setup};

#endif /* PTLS_FFX_H */