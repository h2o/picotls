/*
 * Copyright (c) 2020 Fastly, Kazuho Oku
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
/* Usage:
 * % gcc -Wall -O2 -g -DTARGET_AEAD=ptls_openssl_aes128gcm -DTARGET_HASH=ptls_openssl_sha256 -I include \
 * -I /usr/local/openssl-1.1.1/include lib/picotls.c lib/openssl.c src/speed.c -L /usr/local/openssl-1.1.1/lib -lcrypto -o speed
 * % time ./speed
 *
 * In short, set TARGET_AEAD, TARGET_HASH, compile and link to the necessary source files and/or libraries. Then run.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "picotls.h"

#ifndef TARGET_AEAD
#error "TARGET_AEAD must be set to one of the AEAD ciphers (e.g, ptls_openssl_aes256gcm)
#endif
#ifndef TARGET_HASH
#error "TARGET_HASH must be set to one of the HASH implementations (e.g., ptls_openssl_sha256)
#endif
#ifndef COUNT
#define COUNT 10000000
#endif
#ifndef BLOCK_SIZE
#define BLOCK_SIZE 1024
#endif

extern ptls_aead_algorithm_t TARGET_AEAD;
extern ptls_hash_algorithm_t TARGET_HASH;

int main(int argc, char **argv)
{
    uint8_t input[BLOCK_SIZE] = {0}, output[BLOCK_SIZE + 100], *secret = malloc(TARGET_HASH.digest_size);
    memset(secret, 0, TARGET_HASH.digest_size);

    printf("encrypting %llu bytes\n", (unsigned long long)COUNT * BLOCK_SIZE);

    ptls_aead_context_t *ctx = ptls_aead_new(&TARGET_AEAD, &TARGET_HASH, 1, secret, "foo");
    size_t i;
    for (i = 0; i < COUNT; ++i)
        ptls_aead_encrypt(ctx, output, input, sizeof(input), 0, "hello", 5);
    ptls_aead_free(ctx);

    return 0;
}
