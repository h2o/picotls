#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include "picotls/fusion.h"

int main(int argc, char **argv)
{
    static const uint8_t key[16] = {}, iv[12] = {}, aad[13] = {};
    size_t textlen = 16384;
    ptls_fusion_aesecb_context_t *suppkey = NULL;
    uint8_t suppvec[16] = {};
    int ch, count = 1000000;

    while ((ch = getopt(argc, argv, "b:n:sh")) != -1) {
        switch (ch) {
        case 'b':
            if (sscanf(optarg, "%zu", &textlen) != 1) {
                fprintf(stderr, "failed to parse the number of bytes given by `-b`\n");
                exit(1);
            }
            break;
        case 'n':
            if (sscanf(optarg, "%d", &count) != 1) {
                fprintf(stderr, "failed to parse the number given by `-n`\n");
                exit(1);
            }
            break;
        case 's': {
            static const uint8_t k[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
            suppkey = malloc(sizeof(*suppkey));
            ptls_fusion_aesecb_init(suppkey, k);
        } break;
        default:
            printf("Usage: %s -b <bytes> -s\n"
                   "Options:\n"
                   "    -b <bytes>  specifies the size of the AEAD payload\n"
                   "    -n <count>  number of iterations\n"
                   "    -s          if set, runs the benchmark with supplemental vector\n", argv[0]);
            return 0;
        }
    }
    argc -= optind;
    argv += optind;

    uint8_t *text = malloc(textlen + 16);
    memset(text, 0, textlen + 16);

    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(key, sizeof(aad) + textlen);

    for (int i = 0; i < count; ++i)
        ptls_fusion_aesgcm_encrypt(ctx, iv, aad, sizeof(aad), text, text, textlen, suppkey, suppvec);

    for (int i = 0; i < 16; ++i)
        printf("%02x", text[textlen + i]);
    printf("\n");

    return 0;
}
