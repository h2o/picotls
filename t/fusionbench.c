#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "picotls/fusion.h"

int main(int argc, char **argv)
{
    static const uint8_t key[16] = {}, iv[12] = {}, aad[13] = {};
    size_t textlen = 16384;
    ptls_fusion_aesecb_context_t *suppkey;
    uint8_t suppvec[16] = {};

    if (argc >= 2 && sscanf(argv[1], "%zu", &textlen) != 1) {
        fprintf(stderr, "failed to obtain text length from argument\n");
        return 1;
    }
    if (argc >= 3 && strcmp(argv[2], "1") == 0) {
        static const uint8_t k[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        suppkey = malloc(sizeof(*suppkey));
        ptls_fusion_aesecb_init(suppkey, k);
    }

    uint8_t *text = malloc(textlen + 16);
    memset(text, 0, textlen + 16);

    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(key, sizeof(aad) + textlen);

    for (int i = 0; i < 1000000; ++i)
        ptls_fusion_aesgcm_encrypt(ctx, iv, aad, sizeof(aad), text, text, textlen, suppkey, suppvec);

    for (int i = 0; i < 16; ++i)
        printf("%02x", text[textlen + i]);
    printf("\n");

    return 0;
}
