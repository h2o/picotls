/*
 * Copyright (c) 2018 Fastly, Kazuho Oku
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
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include "picotls.h"
#include "picotls/pembase64.h"
#include "picotls/openssl.h"

static ptls_key_exchange_algorithm_t *key_exchanges[] = {&ptls_openssl_secp256r1,
#ifdef PTLS_OPENSSL_HAS_SECP384R1
                                                         &ptls_openssl_secp384r1,
#endif
#ifdef PTLS_OPENSSL_HAS_SECP521R1
                                                         &ptls_openssl_secp521r1,
#endif
#ifdef PTLS_OPENSSL_HAS_X25519
                                                         &ptls_openssl_x25519,
#endif
                                                         NULL};
static ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, ptls_openssl_cipher_suites};

static int read_esni(void)
{
    ptls_buffer_t buf;
    int ret;

    ptls_buffer_init(&buf, "", 0);

    { /* read */
        int ch;
        while ((ch = fgetc(stdin)) != EOF)
            ptls_buffer_push(&buf, ch);
    }

    const uint8_t *src = buf.base, *end = src + buf.off;

    do {
        ptls_decode_open_block(src, end, 2, {
            ptls_esni_t esni;
            ptls_iovec_t esni_keys;
            size_t i;
            if ((ret = ptls_esni_parse(&ctx, &esni, &esni_keys, src, end)) != 0)
                goto Exit;
            printf("ESNIKeys:\n");
            printf("  key-exchanges:");
            for (i = 0; esni.key_exchanges[i] != NULL; ++i)
                printf(" 0x%04" PRIx16, esni.key_exchanges[i]->algo->id);
            printf("\n");
            printf("  cipher-suites:");
            for (i = 0; esni.cipher_suites[i].cipher_suite != NULL; ++i)
                printf(" 0x%04" PRIx16, esni.cipher_suites[i].cipher_suite->id);
            printf("\n");
            printf("  padded-length: %" PRIu16 "\n", esni.padded_length);
            printf("  not-before: %" PRIu64 "\n", esni.not_before);
            printf("  not-after: %" PRIu64 "\n", esni.not_after);
            char *esni_keys_base64 = malloc(ptls_base64_howlong(esni_keys.len) + 1);
            assert(esni_keys_base64 != NULL);
            ptls_base64_encode(esni_keys.base, esni_keys.len, esni_keys_base64);
            printf("  TXT record: \"%s\" (%zu bytes)\n", esni_keys_base64, strlen(esni_keys_base64));
            free(esni_keys_base64);
            ptls_esni_dispose(&esni);
            src = end;
        });
    } while (src != end);

    ret = 0;
Exit:
    if (ret != 0) {
        fprintf(stderr, "failed to parse ESNI data due to TLS alert: %d\n", ret);
        return 1;
    }
    return 0;
}

static int emit_esni(ptls_key_exchange_algorithm_t **key_exchanges, ptls_cipher_suite_t **cipher_suites, uint16_t padded_length,
                     uint64_t not_before, uint64_t lifetime)
{
    ptls_buffer_t buf;
    ptls_key_exchange_context_t *ctx[256] = {NULL};
    int ret;

    ptls_buffer_init(&buf, "", 0);

    /* struct that contains ESNIKeys and corresponding private keys */
    ptls_buffer_push_block(&buf, 2, {
        ptls_buffer_push_block(&buf, 2, {
            /* build ESNIKeys */
            size_t start = buf.off;
            ptls_buffer_push(&buf, 0, 0, 0, 0); /* checksum, filled later */
            ptls_buffer_push_block(&buf, 2, {
                size_t i;
                for (i = 0; key_exchanges[i] != NULL; ++i) {
                    ptls_iovec_t pubkey;
                    if ((ret = key_exchanges[i]->create(key_exchanges[i], ctx + i, &pubkey)) != 0)
                        goto Exit;
                    if (ctx[i]->save == NULL) {
                        fprintf(stderr,
                                "the selected key-exchange algorithm (id:%" PRIu16 ") does not support private key exportation\n",
                                key_exchanges[i]->id);
                        ret = 1;
                        goto Exit;
                    }
                    ptls_buffer_push16(&buf, key_exchanges[i]->id);
                    ptls_buffer_push_block(&buf, 2, { ptls_buffer_pushv(&buf, pubkey.base, pubkey.len); });
                }
            });
            ptls_buffer_push_block(&buf, 2, {
                size_t i;
                for (i = 0; cipher_suites[i] != NULL; ++i)
                    ptls_buffer_push16(&buf, cipher_suites[i]->id);
            });
            ptls_buffer_push16(&buf, padded_length);
            ptls_buffer_push64(&buf, not_before);
            ptls_buffer_push64(&buf, not_before + lifetime - 1);
            ptls_buffer_push_block(&buf, 2, {});
            { /* fill checksum */
                ptls_hash_context_t *h = ptls_openssl_sha256.create();
                uint8_t d[PTLS_SHA256_DIGEST_SIZE];
                h->update(h, buf.base + start + 4, buf.off - (start + 4));
                h->final(h, d, PTLS_HASH_FINAL_MODE_FREE);
                memcpy(buf.base + start, d, 4);
            }
        });
        /* private keys */
        ptls_buffer_push_block(&buf, 2, {
            size_t i;
            for (i = 0; ctx[i] != NULL; ++i) {
                ptls_buffer_push_block(&buf, 2, {
                    if ((ret = ctx[i]->save(ctx[i], &buf)) != 0)
                        goto Exit;
                });
            }
        });
    });

    /* emit the structure to stdout */
    fwrite(buf.base, 1, buf.off, stdout);
    fflush(stdout);

    ret = 0;
Exit : {
    size_t i;
    for (i = 0; ctx[i] != NULL; ++i)
        ctx[i]->on_exchange(ctx + i, 1, NULL, ptls_iovec_init(NULL, 0));
}
    ptls_buffer_dispose(&buf);
    return ret;
}

static void usage(const char *cmd, int status)
{
    printf("picotls-esni - generates private structure for ESNI\n"
           "\n"
           "Usage: %s [options]\n"
           "Options:\n"
           "  -x <key-exchange>   secp256r1, x25519, ... (default: secp256r1)\n"
           "  -c <cipher-suite>   aes128-gcm, chacha20-poly1305, ...\n"
           "  -d <days>           number of days until expiration (default: 90)\n"
           "  -p <padded-length>  padded length (default: 260)\n"
           "  -r                  reads the private structure from stdin and prints the\n"
           "                      content (e.g., TXT record to be registered). The rest of\n"
           "                      the arguments are ignored when the option is being used.\n"
           "  -h                  prints this help\n"
           "\n"
           "-c and -x can be used multiple times.\n"
           "\n",
           cmd);
    exit(status);
}

int main(int argc, char **argv)
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    struct {
        ptls_key_exchange_algorithm_t *elements[256];
        size_t count;
    } key_exchanges = {{NULL}, 0};
    struct {
        ptls_cipher_suite_t *elements[256];
        size_t count;
    } cipher_suites = {{NULL}, 0};
    uint16_t padded_length = 260;
    uint64_t lifetime = 90 * 86400;

    int ch;
    while ((ch = getopt(argc, argv, "x:c:d:p:rh")) != -1) {
        switch (ch) {
        case 'x': {
            if (strcasecmp("secp256r1", optarg) == 0) {
                key_exchanges.elements[key_exchanges.count++] = &ptls_openssl_secp256r1;
            }
#ifdef PTLS_OPENSSL_HAS_SECP384R1
            else if (strcasecmp("secp384r1", optarg) == 0) {
                key_exchanges.elements[key_exchanges.count++] = &ptls_openssl_secp384r1;
            }
#endif
#ifdef PTLS_OPENSSL_HAS_SECP521R1
            else if (strcasecmp("secp521r1", optarg) == 0) {
                key_exchanges.elements[key_exchanges.count++] = &ptls_openssl_secp521r1;
            }
#endif
#ifdef PTLS_OPENSSL_HAS_X25519
            else if (strcasecmp("x25519", optarg) == 0) {
                key_exchanges.elements[key_exchanges.count++] = &ptls_openssl_x25519;
            }
#endif
            else {
                fprintf(stderr, "unknown key-exchange: %s\n", optarg);
                exit(1);
            }
        } break;
        case 'c': {
            size_t i;
            for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
                if (strcasecmp(ptls_openssl_cipher_suites[i]->aead->name, optarg) == 0)
                    break;
            if (ptls_openssl_cipher_suites[i] == NULL) {
                fprintf(stderr, "unknown cipher-suite: %s\n", optarg);
                exit(1);
            }
            cipher_suites.elements[cipher_suites.count++] = ptls_openssl_cipher_suites[i];
        } break;
        case 'd':
            if (sscanf(optarg, "%" SCNu64, &lifetime) != 1 || lifetime == 0) {
                fprintf(stderr, "lifetime must be a positive integer\n");
                exit(1);
            }
            lifetime *= 86400; /* convert to seconds */
            break;
        case 'p':
            if (sscanf(optarg, "%" SCNu16, &padded_length) != 1 || padded_length == 0) {
                fprintf(stderr, "padded length must be a positive integer\n");
                exit(1);
            }
            break;
        case 'r':
            return read_esni();
        case 'h':
            usage(argv[0], 0);
            break;
        default:
            usage(argv[0], 1);
            break;
        }
    }
    if (cipher_suites.count == 0)
        cipher_suites.elements[cipher_suites.count++] = &ptls_openssl_aes128gcmsha256;
    if (key_exchanges.count == 0)
        key_exchanges.elements[key_exchanges.count++] = &ptls_openssl_secp256r1;
    argc -= optind;
    argv += optind;

    if (emit_esni(key_exchanges.elements, cipher_suites.elements, padded_length, time(NULL), lifetime) != 0) {
        fprintf(stderr, "failed to generate ESNI private structure.\n");
        exit(1);
    }

    return 0;
}
