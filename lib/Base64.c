/*
* Copyright (c) 2016 Christian Huitema <huitema@huitema.net>
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/*
 * Manage Base64 encoding.
 */
#ifdef WIN32
#include "wincompat.h"
#else
#include <sys/time.h>
#endif
#include <string.h>
#include "picotls.h"

static char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char base64_values[] = {
    /* 0x00 to 0x0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x10 to 0x1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x20 to 0x2F. '+' at 2B, '/' at 2F  */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    /* 0x30 to 0x3F -- digits 0 to 9 at 0x30 to 0x39*/
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    /* 0x40 to 0x4F -- chars 'A' to 'O' at 0x41 to 0x4F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 0x50 to 0x5F -- chars 'P' to 'Z' at 0x50 to 0x5A */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    /* 0x60 to 0x6F -- chars 'a' to 'o' at 0x61 to 0x6F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    /* 0x70 to 0x7F -- chars 'p' to 'z' at 0x70 to 0x7A */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

static void base64_cell(unsigned char * data, char * text)
{
    int n[4];

    n[0] = data[0] >> 2;
    n[1] = ((data[0] & 3) << 4) | (data[1] >> 4);
    n[2] = ((data[1] & 15) << 2) | (data[2] >> 6);
    n[3] = data[2] & 63;

    for (int i = 0; i < 4; i++)
    {
        text[i] = base64_alphabet[n[i]];
    }
}

int base64_howlong(int data_length)
{
    return (((data_length + 2) / 3) * 4);
}

int base64_encode(unsigned char * data, int data_len, char * base64_text)
{
    int l = 0;
    int lt = 0;

    while ((data_len - l) >= 3)
    {
        base64_cell(data + l, base64_text + lt);
        l += 3;
        lt += 4;
    }

    switch (data_len - l)
    {
    case 0:
        break;
    case 1:
        base64_text[lt++] = base64_alphabet[data[l] >> 2];
        base64_text[lt++] = base64_alphabet[(data[l] & 3) << 4];
        base64_text[lt++] = '=';
        base64_text[lt++] = '=';
        break;
    case 2:
        base64_text[lt++] = base64_alphabet[data[l] >> 2];
        base64_text[lt++] = base64_alphabet[((data[l] & 3) << 4) | (data[l + 1] >> 4)];
        base64_text[lt++] = base64_alphabet[((data[l + 1] & 15) << 2)];
        base64_text[lt++] = '=';
        break;
    default:
        break;
    }
    base64_text[lt++] = 0;

    return lt;
}

/*
 * TODO: should take into input a line of text, so as to work by increments.
 * Or, find ways to read text into long strings...
 */

void base64_decode_init(struct ptls_base64_decode_state_st * state)
{
    state->nbc = 0;
    state->nbo = 3;
    state->v = 0;
    state->status = PTLS_BASE64_DECODE_IN_PROGRESS;
}

int base64_decode(char * text, struct ptls_base64_decode_state_st * state, ptls_buffer_t *buf)
{
    int ret = 0;
    int decoded[3];
    int text_index = 0;
    char c;
    char vc;

    /* skip initial blanks */
    while (text[text_index] != 0)
    {
        c = text[text_index++];

        if (c == ' ' || c == '/t' || c == '/r' || c == '/n')
        {
            continue;
        }
    }

    while (text[text_index] != 0 && ret == 0 && state->status == PTLS_BASE64_DECODE_IN_PROGRESS)
    {
        c = text[text_index++];
        
        vc = base64_values[c];
        if (vc == -1)
        {
            if (state->nbc == 2 && c == '=' && text[text_index] == '=')
            {
                state->nbc = 4;
                text_index++;
                state->nbo = 1;
                state->v <<= 12;
            }
            else if (state->nbc == 3 && c == '=')
            {
                state->nbc = 4;
                state->nbo = 2;
                state->v <<= 6;
            }
            else
            {
                /* Skip final blanks */
                text_index--;
                while (text[text_index] != 0)
                {
                    c = text[text_index++];

                    if (c == ' ' || c == '/t' || c == '/r' || c == '/n')
                    {
                        continue;
                    }
                }

                /* Should now be at end of buffer */
                if (text[text_index] == 0)
                {
                    break;
                }
                else
                {
                    /* Not at end of buffer, signal a decoding error */
                    state->nbo = 0;
                    state->status = PTLS_BASE64_DECODE_FAILED;
                    ret = PTLS_ERROR_INCORRECT_BASE64;
                }
            }
        }
        else
        {
            state->nbc++;
            state->v <<= 6;
            state->v |= vc;
        }

        if (ret == 0 && state->nbc == 4)
        {
            /* Convert to up to 3 octets */
            for (int j = 0; j < state->nbo; j++)
            {
                decoded[j] = (uint8_t)(state->v >> (8 * (2 - j)));
            }

            ret = ptls_buffer__do_pushv(buf, decoded, state->nbo);

            if (ret == 0)
            {
                /* test for fin or continuation */
                if (state->nbo < 3)
                {
                    /* Check that there are only trainling blanks on this line */
                    while (text[text_index] != 0)
                    {
                        c = text[text_index++];

                        if (c == ' ' || c == '/t' || c == '/r' || c == '/n')
                        {
                            continue;
                        }
                    }
                    if (text[text_index] == 0)
                    {
                        state->status = PTLS_BASE64_DECODE_DONE;
                    }
                    else
                    {
                        state->status = PTLS_BASE64_DECODE_FAILED;
                        ret = PTLS_ERROR_INCORRECT_BASE64;
                    }
                    break;
                }
                else
                {
                    state->v = 0;
                    state->nbo = 3;
                    state->nbc = 0;
                }
            }
        }
    }
    return ret;
}
