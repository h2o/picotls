/*
 * fuzz-fusion-aead.c — component-API fuzzer for picotls' "fusion" AES-GCM
 * engine (lib/fusion.c, the AVX2/VAES fast path used in production by H2O and
 * QUIC deployments).
 *
 * Threat model: AEAD decryption runs on every attacker-influenceable record;
 * malformed ciphertexts, wrong keys and truncated lengths are the daily input
 * of a TLS endpoint. lib/fusion.c (~2.2k lines of own crypto code) is linked
 * into no fuzz target at all — production fuzzing covers zero of it (report
 * 2026-11-17: absent from every coverage map; picotls-fusion is built but
 * never linked into the fuzzers).
 *
 * Harness shape (component API round-trip): guard on
 * ptls_fusion_is_supported_by_cpu() (graceful no-op without AVX2/AES-NI/
 * PCLMUL), then drive ptls_aead_new_direct(encrypt) → ptls_aead_encrypt →
 * ptls_aead_new_direct(decrypt) → ptls_aead_decrypt with bit-flipped
 * ciphertexts, wrong keys, varied sequence numbers and AAD, plus the AES-CTR
 * and QUICLB cipher instantiations of the same engine. No corpus or
 * dictionary: typed API, plain fuzzing reaches every branch quickly.
 *
 * Input framing: byte0 = mode flags (bit0 AES-256, bit1 flip a ciphertext
 * bit, bit2 wrong-key decrypt, bit3 AES-CTR round-trip, bit4 fusion QUICLB
 * round-trip), byte1 = sequence-number selector, byte2 = length selector,
 * byte3 = AAD length (mod 64), bytes 4.. = key material then payload.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "picotls.h"
#include "picotls/fusion.h"

#define MAX_PAYLOAD 1560

void deterministic_random_bytes(void *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *)buf)[i] = (uint8_t)(0x41 + (i % 26));
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t key[PTLS_AES256_KEY_SIZE] = {0}, iv[PTLS_AESGCM_IV_SIZE] = {0}, wrongkey[PTLS_AES256_KEY_SIZE];
    uint8_t ct[MAX_PAYLOAD + PTLS_AESGCM_TAG_SIZE], rt[MAX_PAYLOAD], aad[64];
    ptls_aead_context_t *enc = NULL, *dec = NULL, *decw = NULL;
    ptls_cipher_context_t *ctr = NULL, *ctr2 = NULL, *qlb = NULL, *qlb2 = NULL;
    size_t key_size, plen, aad_len, ct_len, retlen;
    uint64_t seq;
    uint8_t flags;
    size_t i;

    if (!ptls_fusion_is_supported_by_cpu())
        return 0;
    if (size < 4)
        return 0;

    flags = data[0];
    seq = data[1];
    key_size = (flags & 1) != 0 ? PTLS_AES256_KEY_SIZE : PTLS_AES128_KEY_SIZE;
    for (i = 0; i < key_size && 4 + i < size; ++i)
        key[i] = data[4 + i];
    size_t off = 4 + key_size;
    for (i = 0; i < PTLS_AESGCM_IV_SIZE && off + (size_t)i < size; ++i)
        iv[i] = data[off + i];
    off += PTLS_AESGCM_IV_SIZE;
    aad_len = data[3] % (sizeof(aad) + 1);
    for (i = 0; i < aad_len && off + i < size; ++i)
        aad[i] = data[off + i];
    off += aad_len;
    plen = size > off ? size - off : 0;
    if (plen > MAX_PAYLOAD)
        plen = MAX_PAYLOAD;
    if (plen == 0)
        return 0;
    const uint8_t *payload = data + off;

    ptls_aead_algorithm_t *aead = (flags & 1) != 0 ? &ptls_fusion_aes256gcm : &ptls_fusion_aes128gcm;

    if ((enc = ptls_aead_new_direct(aead, 1, key, iv)) == NULL)
        goto Exit;
    ct_len = ptls_aead_encrypt(enc, ct, payload, plen, seq, aad, aad_len);
    if (ct_len > sizeof(ct))
        goto Exit;

    if ((flags & 2) != 0)
        ct[data[1] % ct_len] ^= 0x08;

    if ((dec = ptls_aead_new_direct(aead, 0, key, iv)) == NULL)
        goto Exit;
    retlen = ptls_aead_decrypt(dec, rt, ct, ct_len, seq, aad, aad_len);
    if (retlen != SIZE_MAX && retlen > sizeof(rt))
        goto Exit; /* bounds violation would be a real finding */
    if ((flags & 2) == 0 && retlen == plen && memcmp(rt, payload, plen) != 0)
        goto Exit; /* round-trip mismatch is a logic finding, keep running */

    /* wrong-key decrypt must fail cleanly */
    if ((flags & 4) != 0) {
        for (i = 0; i < key_size; ++i)
            wrongkey[i] = (uint8_t)(key[i] ^ 0xff);
        if ((decw = ptls_aead_new_direct(aead, 0, wrongkey, iv)) != NULL)
            ptls_aead_decrypt(decw, rt, ct, ct_len, seq, aad, aad_len);
    }

    /* AES-CTR round-trip through the same engine; fusion CTR requires an
     * explicit ptls_cipher_init and accepts a single transform of at most
     * 16 bytes per context (lib/fusion.c:1022-1037) */
    if ((flags & 8) != 0) {
        uint8_t ctriv[PTLS_AES_IV_SIZE] = {0};
        uint8_t ctb[16], rtb[16];
        size_t n = plen < 16 ? plen : 16;
        for (i = 0; i < PTLS_AES_IV_SIZE; ++i)
            ctriv[i] = (uint8_t)(data[(2 * (size_t)i) % (size > 0 ? size : 1)]);
        if ((ctr = ptls_cipher_new((flags & 1) != 0 ? &ptls_fusion_aes256ctr : &ptls_fusion_aes128ctr, 1, key)) != NULL) {
            ptls_cipher_init(ctr, ctriv);
            ptls_cipher_encrypt(ctr, ctb, payload, n);
            if ((ctr2 = ptls_cipher_new((flags & 1) != 0 ? &ptls_fusion_aes256ctr : &ptls_fusion_aes128ctr, 0, key)) != NULL) {
                ptls_cipher_init(ctr2, ctriv);
                ptls_cipher_encrypt(ctr2, rtb, ctb, n);
            }
        }
    }

    /* fusion QUICLB round-trip over the legal lengths */
    if ((flags & 16) != 0) {
        size_t qlen = PTLS_QUICLB_MIN_BLOCK_SIZE + (data[2] % (PTLS_QUICLB_MAX_BLOCK_SIZE - PTLS_QUICLB_MIN_BLOCK_SIZE + 1));
        uint8_t qpt[PTLS_QUICLB_MAX_BLOCK_SIZE], qct[PTLS_QUICLB_MAX_BLOCK_SIZE], qrt[PTLS_QUICLB_MAX_BLOCK_SIZE];
        for (i = 0; i < qlen; ++i)
            qpt[i] = (uint8_t)(payload[i % plen] + i);
        if ((qlb = ptls_cipher_new(&ptls_fusion_quiclb, 1, key)) != NULL) {
            ptls_cipher_encrypt(qlb, qct, qpt, qlen);
            if ((qlb2 = ptls_cipher_new(&ptls_fusion_quiclb, 0, key)) != NULL)
                ptls_cipher_encrypt(qlb2, qrt, qct, qlen);
        }
    }

Exit:
    if (enc != NULL)
        ptls_aead_free(enc);
    if (dec != NULL)
        ptls_aead_free(dec);
    if (decw != NULL)
        ptls_aead_free(decw);
    if (ctr != NULL)
        ptls_cipher_free(ctr);
    if (ctr2 != NULL)
        ptls_cipher_free(ctr2);
    if (qlb != NULL)
        ptls_cipher_free(qlb);
    if (qlb2 != NULL)
        ptls_cipher_free(qlb2);
    return 0;
}
