#ifndef PTLS_CRED_BUFFER_H
#define PTLS_CRED_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "picotls.h"

typedef struct ptls_cred_buffer_s {
    char *base;
    size_t len;
    size_t off;
    int owns_base;
#define PTLS_CRED_BUFFER_RPOS(buf) ((buf)->base + (buf)->off)
#define PTLS_CRED_BUFFER_REND(buf) ((buf)->base + (buf)->len)
#define PTLS_CRED_BUFFER_LEFT(buf) ((buf)->len - (buf)->off)
} ptls_cred_buffer_t;

int ptls_cred_buffer_set_from_file(ptls_cred_buffer_t *buf, const char *fname);
int ptls_cred_buffer_set_from_string(ptls_cred_buffer_t *buf, char *s);
void ptls_cred_buffer_dispose(ptls_cred_buffer_t *buf);
void ptls_cred_buffer_rewind(ptls_cred_buffer_t *buf);
char *ptls_cred_buffer_gets(char *s, int n, ptls_cred_buffer_t *buf);

#ifdef __cplusplus
}
#endif

#endif  /* !PTLS_CRED_BUFFER_H */