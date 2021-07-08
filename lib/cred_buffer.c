#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "picotls/cred_buffer.h"

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int cred_buffer_getc(ptls_cred_buffer_t *buf)
{
    return PTLS_CRED_BUFFER_LEFT(buf) > 0 ? buf->base[buf->off++] : -1;
}

static ssize_t fsize(FILE *fp)
{
    long sz;

    if (fseek(fp, 0, SEEK_END) == -1 || (sz = ftell(fp)) == -1) {
        return -1;
    }

    rewind(fp);

    return (ssize_t) sz;
}

/* The caller owns 'mem' and must have called ptls_buffer_init prior to
 * invoking this function */
int ptls_cred_buffer_set_from_file(ptls_cred_buffer_t *buf, const char *fname)
{
    FILE *fp = NULL;
    ssize_t sz;
    char *m = NULL;

#ifdef _WINDOWS
    errno_t err = fopen_s(&fp, fname, "r");
    if (err != 0) {
        return -1;
    }
#else
    fp = fopen(fname, "r");
    if (fp == NULL) {
        return -1;
    }
#endif

    if ((sz = fsize(fp)) == -1 ||
        (m = malloc(sz)) == NULL ||
        fread(m, sz, 1, fp) != 1) {
        goto err;
    }

    (void) fclose(fp);

    buf->base = m;
    buf->len = sz;
    buf->off = 0;
    buf->owns_base = 1;

    return 0;
err:
    if (m)
        free(m);
    if (fp != NULL)
      (void) fclose(fp);

    return -1;
}

int ptls_cred_buffer_set_from_string(ptls_cred_buffer_t *buf, char *s)
{
    buf->base = s;
    buf->len = strlen(s);
    buf->off = 0;
    buf->owns_base = 0;

    return 0;
}

void ptls_cred_buffer_dispose(ptls_cred_buffer_t *buf)
{
    if (buf->owns_base) {
        if (buf->base) {
            free(buf->base);
            buf->base = NULL;
        }
        buf->len = buf->off = 0;
        buf->owns_base = 0;
    }

    return;
}

void ptls_cred_buffer_rewind(ptls_cred_buffer_t *buf)
{
    buf->off = 0;
    return;
}

/* z -> nlptr */
char *ptls_cred_buffer_gets(char *s, int n, ptls_cred_buffer_t *buf)
{
    char *p = s;
    char *z;
    size_t k;
    int c;

    if (n-- <= 1) {
        if (n) return NULL;
        *s = '\0';
        return s;
    }

    while (n) {
        if (PTLS_CRED_BUFFER_RPOS(buf) != PTLS_CRED_BUFFER_REND(buf)) {
            z = memchr(PTLS_CRED_BUFFER_RPOS(buf), '\n', PTLS_CRED_BUFFER_LEFT(buf));
            k = z ? z - PTLS_CRED_BUFFER_RPOS(buf) + 1 : PTLS_CRED_BUFFER_LEFT(buf);
            k = MIN(k, n);
            memcpy(p, PTLS_CRED_BUFFER_RPOS(buf), k);
            buf->off += k;
            p += k;
            n -= k;
            if (z || !n) break;
        }

        if ((c = cred_buffer_getc(buf)) < 0) {
            if (p == s || PTLS_CRED_BUFFER_LEFT(buf) > 0) s = NULL;
            break;
        }

        n--;

        if ((*p++ = c) == '\n') break;
    }

    if (s) *p = '\0';

    return s;
}
