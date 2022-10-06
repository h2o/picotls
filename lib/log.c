/*
 * Copyright (c) 2022 Fastly, Inc., Goro Fuji, Kazuho Oku
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
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include "picotls.h"

#if PTLS_HAVE_LOG

volatile int ptls_log_is_active;

static struct {
    int *fds;
    size_t num_fds;
    size_t num_lost;
    pthread_mutex_t mutex;
} logctx = {.mutex = PTHREAD_MUTEX_INITIALIZER};

size_t ptls_log_num_lost(void)
{
    return logctx.num_lost;
}

int ptls_log_add_fd(int fd)
{
    int ret;

    pthread_mutex_lock(&logctx.mutex);

    int *newfds;
    if ((newfds = realloc(logctx.fds, sizeof(logctx.fds[0]) * (logctx.num_fds + 1))) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    logctx.fds = newfds;
    logctx.fds[logctx.num_fds++] = fd;
    ptls_log_is_active = 1;

    ret = 0; /* success */

Exit:
    pthread_mutex_unlock(&logctx.mutex);
    return ret;
}

#endif

/**
 * Builds a JSON-safe string without double quotes. Supplied buffer MUST be 6x + 1 bytes larger than the input.
 */
static size_t escape_json_unsafe_string(char *buf, const void *unsafe_str, size_t len)
{
    char *dst = buf;
    const uint8_t *src = unsafe_str, *end = src + len;

    for (; src != end; ++src) {
        switch (*src) {
#define MAP(ch, escaped)                                                                                                           \
    case ch: {                                                                                                                     \
        memcpy(dst, (escaped), sizeof(escaped) - 1);                                                                               \
        dst += sizeof(escaped) - 1;                                                                                                \
    } break;

            MAP('"', "\\\"");
            MAP('\\', "\\\\");
            MAP('/', "\\/");
            MAP('\b', "\\b");
            MAP('\f', "\\f");
            MAP('\n', "\\n");
            MAP('\r', "\\r");
            MAP('\t', "\\t");

#undef MAP

        default:
            if (*src < 0x20 || *src == 0x7f) {
                *dst++ = '\\';
                *dst++ = 'u';
                *dst++ = '0';
                *dst++ = '0';
                ptls_byte_to_hex(dst, *src);
                dst += 2;
            } else {
                *dst++ = *src;
            }
            break;
        }
    }
    *dst = '\0';

    return (size_t)(dst - buf);
}

void ptlslog__do_write(const ptls_buffer_t *buf)
{
#if PTLS_HAVE_LOG
    pthread_mutex_lock(&logctx.mutex);

    for (size_t i = 0; i < logctx.num_fds; ++i) {
        ssize_t ret;
        while ((ret = write(logctx.fds[i], buf->base, buf->off)) == -1 && errno == EINTR)
            ;
        if (ret == buf->off) {
            /* success */
        } else if (ret > 0 || (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
            /* partial write or buffer full */
            logctx.num_lost++;
        } else {
            /* write error; close fd and remove the entry of it from the array. */
            close(logctx.fds[i]);
            memmove(logctx.fds + i, logctx.fds + i + 1, sizeof(logctx.fds[0]) * (logctx.num_fds - i - 1));
            logctx.fds = realloc(logctx.fds, sizeof(logctx.fds[0]) * (logctx.num_fds - 1));
            --logctx.num_fds;
        }
    }

    pthread_mutex_unlock(&logctx.mutex);
#endif
}

int ptlslog__do_pushv(ptls_buffer_t *buf, const void *p, size_t l)
{
    if (ptls_buffer_reserve(buf, l) != 0)
        return 0;

    memcpy(buf->base + buf->off, p, l);
    buf->off += l;
    return 1;
}

int ptlslog__do_push_unsafestr(ptls_buffer_t *buf, const char *s, size_t l)
{
    if (ptls_buffer_reserve(buf, l * strlen("\\u0000") + 1) != 0)
        return 0;

    buf->off += escape_json_unsafe_string((char *)(buf->base + buf->off), s, l);
    return 1;
}

int ptlslog__do_push_hexdump(ptls_buffer_t *buf, const void *s, size_t l)
{
    if (ptls_buffer_reserve(buf, l * strlen("ff") + 1) != 0)
        return 0;

    ptls_hexdump((char *)(buf->base + buf->off), s, l);
    buf->off += l * strlen("ff");
    return 1;
}

int ptlslog__do_push_signed32(ptls_buffer_t *buf, int32_t v)
{
    /* TODO optimize */
    char s[sizeof("-2147483648")];
    int len = sprintf(s, "%" PRId32, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_signed64(ptls_buffer_t *buf, int64_t v)
{
    /* TODO optimize */
    char s[sizeof("-9223372036854775808")];
    int len = sprintf(s, "%" PRId64, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_unsigned32(ptls_buffer_t *buf, uint32_t v)
{
    /* TODO optimize */
    char s[sizeof("4294967295")];
    int len = sprintf(s, "%" PRIu32, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}

int ptlslog__do_push_unsigned64(ptls_buffer_t *buf, uint64_t v)
{
    /* TODO optimize */
    char s[sizeof("18446744073709551615")];
    int len = sprintf(s, "%" PRIu64, v);
    return ptlslog__do_pushv(buf, s, (size_t)len);
}