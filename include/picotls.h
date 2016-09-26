/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
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
#ifndef picotls_h
#define picotls_h

#define PICOTLS_ALERT_HANDSHAKE_FAILURE -40
#define PICOTLS_ALERT_DECODE_ERROR -50
#define PICOTLS_ALERT_MISSING_EXTENSION -109

#define PICOTLS_ERROR_HANDSHAKE_INCOMPLETE -100001

typedef struct st_picotls_t picotls_t;

/**
 *
 */
picotls_t *picotls_new(void);
/**
 *
 */
void picotls_free(picotls_t *tls);
/**
 * 
 */
int picotls_handshake(picotls_t *tls, const void *input, size_t *inlen, void *output, size_t *outlen);
/**
 * 
 */
int picotls_decode(picotls_t *tls, const void *encrypted, size_t *enclen, void *dst, size_t *dstlen);
/**
 * 
 */
int picotls_encode(picotls_t *tls, const void *src, size_t *srclen, void *encrypted, size_t *enclen);

#endif
