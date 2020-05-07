#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "picotls/fusion.h"

int main(int argc, char **argv)
{
    static const uint8_t key[16] = {}, iv[12] = {}, aad[13] = {};
    size_t textlen = 16384;

    if (sscanf(argv[1], "%zu", &textlen) != 1) {
        fprintf(stderr, "failed to obtain text length from argument\n");
        return 1;
    }

    uint8_t *text = malloc(textlen + 16);
    memset(text, 0, textlen + 16);

    ptls_fusion_aesgcm_context_t *ctx = ptls_fusion_aesgcm_create(key, sizeof(aad) + textlen);

#if 0
    for (int i = 0; i < 10000; ++i) {
        ptls_fusion_aesgcm_encrypt_vec_t vec[100];
        for (int j = 0; j < 100; ++j) {
            vec[j].iv = iv;
            vec[j].aad = aad;
            vec[j].aadlen = sizeof(aad);
            vec[j].dst = text;
            vec[j].src = text;
            vec[j].srclen = textlen;
        }
        ptls_fusion_aesgcm_encrypt(ctx, vec, 100);
    }
#elif 0
    for (int i = 0; i < 1000000; ++i) {
        ptls_fusion_aesgcm_encrypt_vec_t vec = {
            .iv = iv,
            .aad = aad,
            .aadlen = sizeof(aad),
            .dst = text,
            .src = text,
            .srclen = textlen,
        };
        ptls_fusion_aesgcm_encrypt(ctx, &vec, 1);
    }
#else
    for (int i = 0; i < 1000000; ++i)
        ptls_fusion_aesgcm_encrypt(ctx, iv, aad, sizeof(aad), text, text, textlen);
#endif

    for (int i = 0; i < 16; ++i)
        printf("%02x", text[textlen + i]);
    printf("\n");

    return 0;
}
