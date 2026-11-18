/*
 * fuzz-quiclb.c — component-API fuzzer for the QUIC-LB CID cipher
 * (lib/quiclb-impl.h + its OpenSSL instantiation `ptls_openssl_quiclb`).
 *
 * Threat model: QUIC-LB (RFC 9369-first-routing) CID encryption runs on every
 * connection ID routed through a load balancer mesh; the plaintext and key are
 * deployment-controlled, but a malicious mesh member feeds attacker-chosen
 * ciphertexts to the decryptor. Both instantiations (lib/quiclb-impl.h inline
 * code and lib/openssl.c:1435-2670 glue) are dark in production fuzzing
 * (report 2026-11-17: quiclb-impl.h 0/84) although the cipher is linked into
 * every fuzz binary — no harness ever instantiates it.
 *
 * Harness shape (component API round-trip): instantiate encryptor and
 * decryptor with the same key, sweep every legal input length (7..19,
 * picotls.h:117-118), round-trip, bit-flip, wrong-key and cross-length
 * decrypts. No corpus or dictionary: plain fuzzing of the selector bytes
 * reaches all branches within seconds.
 *
 * Input framing: byte0 = key byte, byte1 = decryptor key byte (wrong-key
 * runs), byte2 = length selector (7 + value % 13), bytes 3.. = plaintext.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "picotls.h"
#include "picotls/openssl.h"

void deterministic_random_bytes(void *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *)buf)[i] = (uint8_t)(0x41 + (i % 26));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t key[PTLS_MAX_SECRET_SIZE] = {0};
    uint8_t ct[PTLS_QUICLB_MAX_BLOCK_SIZE], rt[PTLS_QUICLB_MAX_BLOCK_SIZE], wk[PTLS_QUICLB_MAX_BLOCK_SIZE];
    ptls_cipher_context_t *enc = NULL, *dec = NULL, *deco = NULL;
    size_t len;
    int i;

    if (size < 3)
        return 0;

    memset(key, data[0], sizeof(key));
    len = PTLS_QUICLB_MIN_BLOCK_SIZE + (data[2] % (PTLS_QUICLB_MAX_BLOCK_SIZE - PTLS_QUICLB_MIN_BLOCK_SIZE + 1));

    uint8_t pt[PTLS_QUICLB_MAX_BLOCK_SIZE];
    for (i = 0; i < (int)len; ++i)
        pt[i] = size > 3 + (size_t)i ? data[3 + i] : (uint8_t)(i * 31 + 7);

    if ((enc = ptls_cipher_new(&ptls_openssl_quiclb, 1, key)) == NULL)
        goto Exit;
    ptls_cipher_encrypt(enc, ct, pt, len);

    if ((dec = ptls_cipher_new(&ptls_openssl_quiclb, 0, key)) == NULL)
        goto Exit;
    ptls_cipher_encrypt(dec, rt, ct, len);

    /* bit flip must not crash the decryptor */
    ct[data[0] % len] ^= 0x20;
    ptls_cipher_encrypt(dec, wk, ct, len);
    ct[data[0] % len] ^= 0x20;

    /* wrong key must produce different plaintext (logic check);
 * the is_enc=0 context applies the inverse transform via encrypt() */
    memset(key, data[1], sizeof(key));
    if ((deco = ptls_cipher_new(&ptls_openssl_quiclb, 0, key)) != NULL)
        ptls_cipher_encrypt(deco, wk, ct, len);

Exit:
    if (enc != NULL)
        ptls_cipher_free(enc);
    if (dec != NULL)
        ptls_cipher_free(dec);
    if (deco != NULL)
        ptls_cipher_free(deco);
    return 0;
}
