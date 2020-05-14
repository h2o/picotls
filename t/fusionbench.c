#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "picotls/fusion.h"

int main(int argc, char **argv)
{
    static const uint8_t key[16] = {}, aad[13] = {};
    size_t textlen = 16384;
    ptls_aead_supplementary_encryption_t *supp = NULL;
    int ch, decrypt = 0, count = 1000000;

    while ((ch = getopt(argc, argv, "b:dn:sh")) != -1) {
        switch (ch) {
        case 'b':
            if (sscanf(optarg, "%zu", &textlen) != 1) {
                fprintf(stderr, "failed to parse the number of bytes given by `-b`\n");
                exit(1);
            }
            break;
        case 'd':
            decrypt = 1;
            break;
        case 'n':
            if (sscanf(optarg, "%d", &count) != 1) {
                fprintf(stderr, "failed to parse the number given by `-n`\n");
                exit(1);
            }
            break;
        case 's': {
            static const uint8_t k[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            supp = malloc(sizeof(*supp));
            supp->ctx = ptls_cipher_new(&ptls_fusion_aes128ctr, 1, k);
        } break;
        default:
            printf("Usage: %s -b <bytes> -s\n"
                   "Options:\n"
                   "    -b <bytes>  specifies the size of the AEAD payload\n"
                   "    -d          test decryption\n"
                   "    -n <count>  number of iterations\n"
                   "    -s          if set, runs the benchmark with supplemental vector\n",
                   argv[0]);
            return 0;
        }
    }
    argc -= optind;
    argv += optind;

    uint8_t *text = malloc(textlen + 16);
    memset(text, 0, textlen + 16);
    if (supp != NULL)
        supp->input = textlen >= 2 ? text + 2 : text + textlen;

    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_new(key, sizeof(aad) + textlen);

    if (!decrypt) {
        for (int i = 0; i < count; ++i)
            ptls_fusion_aesgcm_encrypt(ctx, text, text, textlen, _mm_setzero_si128(), aad, sizeof(aad), supp);
    } else {
        uint8_t tag[16] = {};
        for (int i = 0; i < count; ++i)
            ptls_fusion_aesgcm_decrypt(ctx, text, text, textlen, _mm_setzero_si128(), aad, sizeof(aad), &tag);
    }

    for (int i = 0; i < 16; ++i)
        printf("%02x", text[i]);
    printf("\n");
    for (int i = 0; i < 16; ++i)
        printf("%02x", text[textlen + i]);
    printf("\n");

    return 0;
}
