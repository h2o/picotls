/*
 * Copyright (c) 2025 Fastly, Kazuho Oku
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
#ifndef picotls_quiclb_h
#define picotls_quiclb_h

/**
 * calculates X ^ AES(mask_and_expand(Y)), assuming the first argument is to a context of ptls_foo_aes128ecb
 */
static inline void picotls_quiclb_one_round(void *aesecb, uint64_t *dest, const uint64_t *x, const uint64_t *y,
                                            const uint64_t *mask, const uint64_t *len_pass)
{
    for (size_t i = 0; i < PTLS_AES_BLOCK_SIZE / sizeof(dest[0]); ++i)
        dest[i] = (y[i] & mask[i]) | len_pass[i];

    ptls_cipher_encrypt(aesecb, dest, dest, PTLS_AES_BLOCK_SIZE);

    for (size_t i = 0; i < PTLS_AES_BLOCK_SIZE / sizeof(dest[0]); ++i)
        dest[i] ^= x[i];
}

static inline void picotls_quiclb_split_input(uint8_t *l, uint8_t *r, const uint8_t *input, size_t len)
{
    size_t i;
    for (i = 0; i < (len + 1) / 2; ++i)
        l[i] = input[i];
    for (; i < PTLS_AES_BLOCK_SIZE; ++i)
        l[i] = 0;
    for (i = 0; i < (len + 1) / 2; ++i)
        r[i] = input[i + len / 2];
    for (; i < PTLS_AES_BLOCK_SIZE; ++i)
        r[i] = 0;
}

static inline void picotls_quiclb_merge_output(uint8_t *output, size_t len, const uint8_t *l, const uint8_t *r)
{
    uint8_t *outp = output;

    for (size_t i = 0; i < len / 2; ++i)
        *outp++ = l[i];

    if (len % 2 == 0) {
        for (size_t i = 0; i < len / 2; ++i)
            *outp++ = r[i];
    } else {
        *outp++ = (l[len / 2] & 0xf0) | (r[0] & 0x0f);
        for (size_t i = 0; i < len / 2; ++i)
            *outp++ = r[i + 1];
    }
}

static inline void picotls_quiclb_transform(void *aesecb, void *output, const void *input, size_t len, int encrypt,
                                            void (*one_round)(void *aesecb, uint64_t *dest, const uint64_t *x, const uint64_t *y,
                                                              const uint64_t *mask, const uint64_t *len_pass))
{
    static const struct quiclb_mask_t {
        union {
            uint8_t bytes[PTLS_AES_BLOCK_SIZE];
            uint64_t u64[PTLS_AES_BLOCK_SIZE / sizeof(uint64_t)];
        } l, r;
    } masks[] = {
        {{{0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff}}},                                                 /* 7 (MIN_LEN) */
        {{{0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff}}},                                                 /* 8 */
        {{{0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff}}},                                     /* 9 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff}}},                                     /* 10 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff}}},                         /* 11 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},                         /* 12 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},             /* 13 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}},             /* 14 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}}, {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 15 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}, {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 16 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}},
         {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 17 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
         {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}}, /* 18 */
        {{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf0}},
         {{0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}} /* 19 */
    };

    assert(PTLS_QUICLB_MIN_BLOCK_SIZE <= len && len <= PTLS_QUICLB_MAX_BLOCK_SIZE);
    PTLS_BUILD_ASSERT(PTLS_QUICLB_MAX_BLOCK_SIZE == PTLS_QUICLB_MIN_BLOCK_SIZE + PTLS_ELEMENTSOF(masks) - 1);

    const struct quiclb_mask_t *mask = &masks[len - PTLS_QUICLB_MIN_BLOCK_SIZE];
    union {
        uint8_t bytes[PTLS_AES_BLOCK_SIZE];
        uint64_t u64[PTLS_AES_BLOCK_SIZE / sizeof(uint64_t)];
    } l0, r0, r1, l1, r2, l2, len_pass = {{0}};
    len_pass.bytes[14] = (uint8_t)len;

#define ROUND(rnd, dest, x, y, mask_side)                                                                                          \
    do {                                                                                                                           \
        len_pass.bytes[15] = (rnd);                                                                                                \
        one_round(aesecb, (dest).u64, (x).u64, (y).u64, mask->mask_side.u64, len_pass.u64);                                        \
    } while (0)

    if (encrypt) {
        picotls_quiclb_split_input(l0.bytes, r0.bytes, input, len);
        ROUND(1, r1, r0, l0, l);
        ROUND(2, l1, l0, r1, r);
        ROUND(3, r2, r1, l1, l);
        ROUND(4, l2, l1, r2, r);
        picotls_quiclb_merge_output(output, len, l2.bytes, r2.bytes);
    } else {
        picotls_quiclb_split_input(l2.bytes, r2.bytes, input, len);
        ROUND(4, l1, l2, r2, r);
        ROUND(3, r1, r2, l1, l);
        ROUND(2, l0, l1, r1, r);
        ROUND(1, r0, r1, l0, l);
        picotls_quiclb_merge_output(output, len, l0.bytes, r0.bytes);
    }

#undef ROUND
}

#endif
