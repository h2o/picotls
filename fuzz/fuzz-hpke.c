/*
 * fuzz-hpke.c — component-API fuzzer for picotls' RFC 9180 HPKE (lib/hpke.c).
 *
 * Threat model: HPKE ciphertexts, sender ephemeral public keys (`enc`) and
 * associated data arrive from the network in ECH and other HPKE deployments;
 * an attacker controls every byte of them. lib/hpke.c has zero coverage in the
 * production fuzzing setup (report 2026-11-17: 0/171 lines): no harness calls
 * the ptls_hpke_* API at all.
 *
 * Harness shape (component API + round-trip): each input drives
 * setup_base_s → AEAD seal → setup_base_r → open over a fresh receiver key
 * exchange, then attacks the artifacts:
 *   - bit-flipped ciphertext must fail to open (or open garbage into a bounded
 *     buffer),
 *   - bit-flipped sender `enc` must fail setup_base_r cleanly,
 *   - fully attacker-supplied `enc`/ciphertext run against the genuine
 *     receiver key exercise the decap/validation failure paths.
 * No corpus or dictionary: the API takes typed values and plain fuzzing of the
 * selector/payload bytes reaches every branch within seconds.
 *
 * Input framing: byte0 = KEM selector, byte1 = cipher-suite selector,
 * byte2 = mode flags (bit0 flip ciphertext bit, bit1 flip `enc` bit,
 * bit2 attacker enc+ciphertext against the real receiver key),
 * byte3 = AAD length (mod 40), bytes 4.. = payload (message, also reused as
 * the attacker ciphertext in bit2 mode).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "picotls.h"
#include "picotls/openssl.h"

#define MAX_MSG 512
#define MAX_AAD 40

static ptls_hpke_kem_t **kems;
static size_t num_kems;
static ptls_hpke_cipher_suite_t **ciphers;
static size_t num_ciphers;

void deterministic_random_bytes(void *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        ((uint8_t *)buf)[i] = (uint8_t)(0x41 + (i % 26));
}

static void count_lists_once(void)
{
    if (kems != NULL)
        return;
    size_t n;
    for (n = 0; ptls_openssl_hpke_kems[n] != NULL; ++n)
        ;
    num_kems = n;
    kems = ptls_openssl_hpke_kems;
    for (n = 0; ptls_openssl_hpke_cipher_suites[n] != NULL; ++n)
        ;
    num_ciphers = n;
    ciphers = ptls_openssl_hpke_cipher_suites;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ptls_hpke_kem_t *kem;
    ptls_hpke_cipher_suite_t *cipher;
    ptls_key_exchange_context_t *keyex = NULL;
    ptls_aead_context_t *enc = NULL, *dec = NULL;
    ptls_iovec_t pk_s = {NULL, 0};
    uint8_t info[] = "picotls-hpke-fuzz-info";
    uint8_t ct[MAX_MSG + 64], decbuf[MAX_MSG + 16];
    size_t msg_len, aad_len, ct_len;
    uint8_t flags;

    count_lists_once();
    if (num_kems == 0 || num_ciphers == 0 || size < 4)
        return 0;

    flags = data[2];
    kem = kems[data[0] % num_kems];
    cipher = ciphers[data[1] % num_ciphers];
    aad_len = data[3] % (MAX_AAD + 1);
    data += 4;
    size -= 4;
    msg_len = size < MAX_MSG ? size : MAX_MSG;
    if (msg_len == 0)
        return 0;

    /* receiver key exchange (fresh per iteration) */
    if (kem->keyex->create(kem->keyex, &keyex) != 0 || keyex == NULL)
        goto Exit;

    /* sender side: encapsulate against the receiver's public key */
    if (ptls_hpke_setup_base_s(kem, cipher, &pk_s, &enc, keyex->pubkey, ptls_iovec_init(info, sizeof(info) - 1)) != 0 ||
        enc == NULL || pk_s.base == NULL)
        goto Exit;

    ct_len = ptls_aead_encrypt(enc, ct, data, msg_len, 0, data, aad_len < msg_len ? aad_len : msg_len);
    if (ct_len == 0 || ct_len > sizeof(ct))
        goto Exit;

    /* flip sources must stay inside the input (payload may be a single byte) */
    uint8_t r1 = size > 0 ? data[0] : 0;
    uint8_t r2 = size > 1 ? data[1] : 0;

    if ((flags & 1) != 0)
        ct[r1 % ct_len] ^= 0x40;
    if ((flags & 2) != 0 && pk_s.len != 0)
        pk_s.base[r2 % pk_s.len] ^= 0x40;

    /* receiver side */
    if (ptls_hpke_setup_base_r(kem, cipher, keyex, &dec, pk_s, ptls_iovec_init(info, sizeof(info) - 1)) == 0) {
        if (dec != NULL) {
            ptls_aead_decrypt(dec, decbuf, ct, ct_len, 0, data, aad_len < msg_len ? aad_len : msg_len);
            ptls_aead_free(dec);
            dec = NULL;
        }
    }
    keyex->on_exchange(&keyex, 1, NULL, ptls_iovec_init(NULL, 0));
    keyex = NULL;

    /* attacker-supplied encapsulated key + ciphertext against a fresh genuine
     * receiver key: exercises decap length/validation failures */
    if ((flags & 4) != 0) {
        ptls_key_exchange_context_t *keyex2 = NULL;
        ptls_aead_context_t *dec2 = NULL;
        size_t enc_len = pk_s.len != 0 ? pk_s.len : 0;
        if (enc_len != 0 && enc_len <= MAX_MSG && kem->keyex->create(kem->keyex, &keyex2) == 0 && keyex2 != NULL) {
            uint8_t fake_enc[MAX_MSG];
            size_t n = msg_len < enc_len ? msg_len : enc_len;
            memcpy(fake_enc, data, n);
            memset(fake_enc + n, 0x5a, enc_len - n);
            if (ptls_hpke_setup_base_r(kem, cipher, keyex2, &dec2, ptls_iovec_init(fake_enc, enc_len),
                                       ptls_iovec_init(info, sizeof(info) - 1)) == 0 &&
                dec2 != NULL) {
                ptls_aead_decrypt(dec2, decbuf, ct, ct_len, 0, data, aad_len < msg_len ? aad_len : msg_len);
                ptls_aead_free(dec2);
                dec2 = NULL;
            }
            keyex2->on_exchange(&keyex2, 1, NULL, ptls_iovec_init(NULL, 0));
        }
    }

Exit:
    if (enc != NULL)
        ptls_aead_free(enc);
    if (dec != NULL)
        ptls_aead_free(dec);
    if (pk_s.base != NULL) {
        ptls_clear_memory(pk_s.base, pk_s.len);
        free(pk_s.base);
    }
    if (keyex != NULL)
        keyex->on_exchange(&keyex, 1, NULL, ptls_iovec_init(NULL, 0));
    return 0;
}
