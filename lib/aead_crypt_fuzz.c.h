/**
 * This file defines AEAD functions for use with fuzz testing. There are
 * definitions for general (i.e. non-fuzzing) use in aead_crypt.h.
 */

static size_t aead_encrypt(struct st_ptls_traffic_protection_t *ctx, void *output, const void *input, size_t inlen,
                           uint8_t content_type)
{
    memcpy(output, input, inlen);
    memcpy(output + inlen, &content_type, 1);
    return inlen + 1 + 16;
}

static int aead_decrypt(struct st_ptls_traffic_protection_t *ctx, void *output, size_t *outlen, const void *input, size_t inlen)
{
    if (inlen < 16) {
        return PTLS_ALERT_BAD_RECORD_MAC;
    }
    memcpy(output, input, inlen - 16);
    *outlen = inlen - 16;  // removing the 16 bytes of tag
    return 0;
}
