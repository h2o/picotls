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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "picotls.h"
#include "picotls/minicrypto.h"

static char ptls_base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char ptls_base64_values[] = {
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

static void ptls_base64_cell(unsigned char * data, char * text)
{
    int n[4];

    n[0] = data[0] >> 2;
    n[1] = ((data[0] & 3) << 4) | (data[1] >> 4);
    n[2] = ((data[1] & 15) << 2) | (data[2] >> 6);
    n[3] = data[2] & 63;

    for (int i = 0; i < 4; i++)
    {
        text[i] = ptls_base64_alphabet[n[i]];
    }
}

int ptls_base64_howlong(int data_length)
{
    return (((data_length + 2) / 3) * 4);
}

int ptls_base64_encode(unsigned char * data, int data_len, char * ptls_base64_text)
{
    int l = 0;
    int lt = 0;

    while ((data_len - l) >= 3)
    {
        ptls_base64_cell(data + l, ptls_base64_text + lt);
        l += 3;
        lt += 4;
    }

    switch (data_len - l)
    {
    case 0:
        break;
    case 1:
        ptls_base64_text[lt++] = ptls_base64_alphabet[data[l] >> 2];
        ptls_base64_text[lt++] = ptls_base64_alphabet[(data[l] & 3) << 4];
        ptls_base64_text[lt++] = '=';
        ptls_base64_text[lt++] = '=';
        break;
    case 2:
        ptls_base64_text[lt++] = ptls_base64_alphabet[data[l] >> 2];
        ptls_base64_text[lt++] = ptls_base64_alphabet[((data[l] & 3) << 4) | (data[l + 1] >> 4)];
        ptls_base64_text[lt++] = ptls_base64_alphabet[((data[l + 1] & 15) << 2)];
        ptls_base64_text[lt++] = '=';
        break;
    default:
        break;
    }
    ptls_base64_text[lt++] = 0;

    return lt;
}

/*
 * Take into input a line of text, so as to work by increments.
 * The intermediate text of the decoding is kept in a state variable.
 * The decoded data is accumulated in a PTLS buffer.
 * The parsing is consistent with the lax definition in RFC 7468
 */

void ptls_base64_decode_init(struct ptls_base64_decode_state_st * state)
{
    state->nbc = 0;
    state->nbo = 3;
    state->v = 0;
    state->status = PTLS_BASE64_DECODE_IN_PROGRESS;
}

int ptls_base64_decode(char * text, struct ptls_base64_decode_state_st * state, ptls_buffer_t *buf)
{
    int ret = 0;
    uint8_t decoded[3];
    int text_index = 0;
    int c;
    char vc;

    /* skip initial blanks */
    while (text[text_index] != 0)
    {
        c = text[text_index];

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
        {
            text_index++;
        }
        else
        {
            break;
        }
    }

    while (text[text_index] != 0 && ret == 0 && state->status == PTLS_BASE64_DECODE_IN_PROGRESS)
    {
        c = text[text_index++];
        
        vc = ptls_base64_values[c];
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

                    if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0B || c == 0x0C)
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

                        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0x0B || c == 0x0C)
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

/*
 * Basic ASN1 validation and optional print-out
 */

static char const * asn1_type_classes[4] = {
	"Universal",
	"Application",
	"Context-specific",
	"Private"
};

static char const * asn1_universal_types[] = {
	"End-of-Content",
	"BOOLEAN",
	"INTEGER",
	"BIT STRING",
	"OCTET STRING",
	"NULL",
	"OBJECT IDENTIFIER",
	"Object Descriptor",
	"EXTERNAL",
	"REAL",
	"ENUMERATED",
	"EMBEDDED PDV",
	"UTF8String",
	"RELATIVE-OID",
	"Reserved (16)",
	"Reserved (17)",
	"SEQUENCE",
	"SET",
	"NumericString",
	"PrintableString",
	"T61String",
	"VideotexString",
	"IA5String",
	"UTCTime",
	"GeneralizedTime",
	"GraphicString",
	"VisibleString",
	"GeneralString",
	"UniversalString",
	"CHARACTER STRING",
	"BMPString"
};


/* For debugging
*/

static void data_dump(uint8_t * bytes, size_t length, FILE* F)
{
	size_t byte_index = 0;

	while (byte_index < length)
	{
		fprintf(F, "%06x ", (uint32_t) byte_index);
		for (size_t i = 0; i < 32 && byte_index < length; i++, byte_index++)
		{
			fprintf(F, "%02x", bytes[byte_index]);
			if ((i & 3) == 3)
			{
				fprintf(F, " ");
			}
		}
		fprintf(F, "\n");
	}
}

static size_t nb_asn1_universal_types = sizeof(asn1_universal_types) / sizeof(char const *);

static void ptls_asn1_print_indent(int level, FILE * F)
{
	for (int indent = 0; indent <= level; indent++)
	{
		fprintf(F, "   ");
	}
}


static size_t ptls_asn1_error_message(char const * error_label, size_t bytes_max, size_t byte_index, 
	int * decode_error, int level, FILE * F)
{
	if (F != NULL)
	{
		ptls_asn1_print_indent(level, F);
		fprintf(F, "Error: %s (near position: %d (0x%x) out of %d)", 
			error_label, (int) byte_index, (uint32_t) byte_index, (int)bytes_max);
	}
	*decode_error = 1;
	return bytes_max;
}

static void ptls_asn1_dump_content(uint8_t * bytes, size_t bytes_max, size_t byte_index, FILE * F)
{
	if (F != NULL && bytes_max > byte_index)
	{
		size_t nb_bytes = bytes_max - byte_index;

		fprintf(F, " ");

		for (size_t i = 0; i < 16 && i < nb_bytes; i++)
		{
			fprintf(F, "%02x", bytes[byte_index + i]);
		}

		if (nb_bytes > 16)
		{
			fprintf(F, "...");
		}
	}
}

size_t ptls_asn1_read_type(uint8_t * bytes, size_t bytes_max,
	int * structure_bit, int * type_class, uint32_t * type_number,
	int * decode_error, int level, FILE * F)
{
	/* Get the type byte */
	size_t byte_index = 1;
	uint8_t first_byte = bytes[0];
	*structure_bit = (first_byte >> 5) & 1;
	*type_class = (first_byte >> 6) & 3;
	*type_number = first_byte & 31;

	if (*type_number == 31)
	{
		uint32_t long_type = 0;
		const uint32_t type_number_limit = 0x07FFFFFFF;
		int next_byte;
		int end_found = 0;

		while (byte_index < bytes_max && long_type <= type_number_limit) {
			next_byte = bytes[byte_index++];
			long_type <<= 7;
			long_type |= next_byte & 127;
			if ((next_byte & 128) == 0)
			{
				end_found = 1;
				break;
			}
		}

		if (end_found)
		{
			*type_number = long_type;
		}
		else
		{
			/* This is an error */
			byte_index = ptls_asn1_error_message("Incorrect type coding", bytes_max, byte_index,
				decode_error, level, F);
		}
	}

	return byte_index;
}

void ptls_asn1_print_type(int type_class, uint32_t type_number, int level, FILE * F)
{
	/* Print the type */
	ptls_asn1_print_indent(level, F);
	if (type_class == 0 && type_number < nb_asn1_universal_types)
	{
		fprintf(F, "%s", asn1_universal_types[type_number]);
	}
	else if (type_class == 2)
	{
		fprintf(F, "[%d]", type_number);
	}
	else
	{
		fprintf(F, "%s[%d]", asn1_type_classes[type_class], type_number);
	}
}

size_t ptls_asn1_read_length(uint8_t * bytes, size_t bytes_max, size_t byte_index,
	uint32_t * length, int * indefinite_length, size_t * last_byte,
	int * decode_error, int level, FILE * F)
{
	int length_of_length = 0;

	*indefinite_length = 0;
	*length = 0;
	*last_byte = bytes_max;

	if (byte_index < bytes_max)
	{
		*length = bytes[byte_index++];
		if ((*length & 128) != 0)
		{
			length_of_length = *length & 127;
			*length = 0;

			if (byte_index + length_of_length >= bytes_max)
			{
				/* This is an error */
				byte_index = ptls_asn1_error_message("Incorrect length coding", bytes_max, byte_index,
					decode_error, level, F);
			}
			else
			{
				for (int i = 0; i < length_of_length && byte_index < bytes_max; i++)
				{
					*length <<= 8;
					*length |= bytes[byte_index++];
				}

				if (length_of_length == 0)
				{
					*last_byte = bytes_max;
					*indefinite_length = 1;
				}
				else
				{
					*last_byte = byte_index + *length;
				}
			}
		}
		else
		{
			*last_byte = byte_index + *length;
		}

		if (*decode_error == 0)
		{
			/* TODO: verify that the length makes sense */
			if (*last_byte > bytes_max)
			{
				byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index,
					decode_error, level, F);
			}
		}
	}

	return byte_index;
}

size_t ptls_asn1_get_expected_type_and_length(uint8_t * bytes, size_t bytes_max, size_t byte_index,
	uint8_t expected_type, uint32_t * length, int * indefinite_length, size_t * last_byte,
	int * decode_error, FILE * log_file)
{
	int is_indefinite = 0;

	/* Check that the expected type is present */
	if (bytes[byte_index] != expected_type)
	{
		byte_index = ptls_asn1_error_message("Unexpected type", bytes_max, byte_index,
			decode_error, 0, log_file);
		*decode_error = PTLS_ERROR_INCORRECT_PEM_SYNTAX;
	}
	else
	{
		/* get length of element */
		byte_index++;
		byte_index = ptls_asn1_read_length(bytes, bytes_max, byte_index,
			length, &is_indefinite, last_byte, decode_error, 0, log_file);

		if (indefinite_length != NULL)
		{
			*indefinite_length = is_indefinite;
		}
		else if (is_indefinite)
		{
			byte_index = ptls_asn1_error_message("Incorrect length for DER", bytes_max, byte_index,
				decode_error, 0, log_file);
			*decode_error = PTLS_ERROR_INCORRECT_PEM_SYNTAX;
		}
	}

	return byte_index;
}

size_t ptls_asn1_validation_recursive(uint8_t * bytes, size_t bytes_max, 
    int * decode_error, int level, FILE * F)
{
    /* Get the type byte */
	int structure_bit = 0;
	int type_class = 0;
    uint32_t type_number = 0;
    uint32_t length = 0;
    int indefinite_length = 0;
    size_t last_byte = 0;
	/* Decode the type */
	size_t byte_index = ptls_asn1_read_type(bytes, bytes_max, &structure_bit, &type_class, &type_number,
		decode_error, level, F);

	if (*decode_error == 0 && F != NULL)
	{
		ptls_asn1_print_type(type_class, type_number, level, F);
	}


    /* Get the length */
	byte_index = ptls_asn1_read_length(bytes, bytes_max, byte_index,
		&length, &indefinite_length, &last_byte,
		decode_error, level, F);

	if (last_byte <= bytes_max)
	{
		if (structure_bit)
		{
			/* If structured, recurse on a loop */
			if (F != NULL)
			{
				fprintf(F, " {\n");
			}

			while (byte_index < last_byte)
			{
				if (indefinite_length != 0 &&
					bytes[byte_index] == 0)
				{
					if (byte_index + 2 > bytes_max ||
						bytes[byte_index + 1] != 0)
					{
						byte_index = ptls_asn1_error_message("EOC: Incorrect indefinite length",
							bytes_max, byte_index, decode_error, level + 1, F);
					}
					else
					{
						if (F != NULL)
						{
							ptls_asn1_print_indent(level, F);
							fprintf(F, "EOC\n");
						}
						byte_index += 2;
						break;
					}
				}
				else
				{
					byte_index += ptls_asn1_validation_recursive(
						bytes + byte_index, last_byte - byte_index,
						decode_error, level + 1, F);

					if (*decode_error)
					{
						byte_index = bytes_max;
						break;
					}
				}

				if (F != NULL)
				{
					if (byte_index < last_byte)
					{
						fprintf(F, ",");
					}
					fprintf(F, "\n");
				}
			}


			if (F != NULL)
			{
				ptls_asn1_print_indent(level, F);
				fprintf(F, "}");
			}
		}
		else
		{
			ptls_asn1_dump_content(bytes, last_byte, byte_index, F);
			byte_index = last_byte;
		}
	}

    return byte_index;
}

int ptls_asn1_validation(uint8_t * bytes, size_t length, FILE * F)
{
	int ret = 0;
	int decode_error = 0;
	size_t decoded = ptls_asn1_validation_recursive(bytes, length,
		&decode_error, 0, F);

	if (decode_error)
	{
		ret = PTLS_ERROR_INCORRECT_BER_ENCODING;
	}
	else
	if (decoded < length)
	{
		ret = PTLS_ERROR_INCORRECT_BER_ENCODING;
		if (F != NULL)
		{
			fprintf(F, "Type too short, %d bytes only out of %d\n",
				(int)decoded, (int)length);
		}
	}

	return ret;
}

/*
 * Reading a PEM file, to get an object:
 *
 * - Find first object, get the object name.
 * - If object label is what the application expects, parse, else skip to end.
 *
 * The following labels are defined in RFC 7468:
 * 
 * Sec. Label                  ASN.1 Type              Reference Module
 * ----+----------------------+-----------------------+---------+----------
 * 5  CERTIFICATE            Certificate             [RFC5280] id-pkix1-e
 * 6  X509 CRL               CertificateList         [RFC5280] id-pkix1-e
 * 7  CERTIFICATE REQUEST    CertificationRequest    [RFC2986] id-pkcs10
 * 8  PKCS7                  ContentInfo             [RFC2315] id-pkcs7*
 * 9  CMS                    ContentInfo             [RFC5652] id-cms2004
 * 10 PRIVATE KEY            PrivateKeyInfo ::=      [RFC5208] id-pkcs8
 *                           OneAsymmetricKey        [RFC5958] id-aKPV1
 * 11 ENCRYPTED PRIVATE KEY  EncryptedPrivateKeyInfo [RFC5958] id-aKPV1
 * 12 ATTRIBUTE CERTIFICATE  AttributeCertificate    [RFC5755] id-acv2
 * 13 PUBLIC KEY             SubjectPublicKeyInfo    [RFC5280] id-pkix1-e
 */

static int ptls_compare_separator_line(char * line, char* begin_or_end, char * label)
{
    int ret = strncmp(line, "-----", 5);
    int text_index = 5;

    if (ret == 0)
    {
        int begin_or_end_length = strlen(begin_or_end);
        ret = strncmp(line + text_index, begin_or_end, begin_or_end_length);
        text_index += begin_or_end_length;
    }

    if (ret == 0)
    {   
        ret = line[text_index] - ' ';
        text_index++;
    }

    if (ret == 0)
    {
        int label_length = strlen(label);
        ret = strncmp(line + text_index, label, label_length);
        text_index += label_length;
    }

    if (ret == 0)
    {
        ret = strncmp(line + text_index, "-----", 5);
    }

    return ret;
}

static int ptls_get_pem_object(FILE * F, char * label, ptls_buffer_t *buf, FILE* log_file)
{
    int ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
    char line[256];
    struct ptls_base64_decode_state_st state;

    /* Get the label on a line by itself */
    while (fgets(line, 256, F))
    {
        if (ptls_compare_separator_line(line, "BEGIN", label) == 0)
        {
            ret = 0;
            ptls_base64_decode_init(&state);
            break;
        }
    }
    /* Get the data in the buffer */
    while (ret == 0 && fgets(line, 256, F))
    {
        if (ptls_compare_separator_line(line, "END", label) == 0)
        {
            if (state.status == PTLS_BASE64_DECODE_DONE ||
                (state.status == PTLS_BASE64_DECODE_IN_PROGRESS && state.nbc == 0))
            {
                ret = 0;
            }
            else
            {
                ret = PTLS_ERROR_INCORRECT_BASE64;
            }
            break;
        }
        else
        {
            ret = ptls_base64_decode(line, &state, buf);
        }
    }

	if (ret == 0)
	{
		ret = ptls_asn1_validation(buf->base, buf->off, log_file);
		if (log_file != NULL)
		{
			fprintf(log_file, "\n");
		}

		if (ret != 0)
		{
			data_dump(buf->base, buf->off, log_file);
		}
	}
    return ret;
}

int ptls_pem_get_objects(char const * pem_fname, char * label, 
	ptls_iovec_t ** list, size_t list_max, size_t * nb_objects, FILE* log_file)
{
    FILE * F;
    int ret = 0;
    size_t count = 0;
#ifdef WIN32
    errno_t err = fopen_s(&F, pem_fname, "r");
    if (err != 0)
    {
        ret = -1;
    }
#else
    F = fopen(pem_fname, "r");
    if (F == NULL)
    {
        ret = -1;
    }
#endif


    *nb_objects = 0;

    if (ret == 0)
    {
        while (count < list_max)
        {
			ptls_buffer_t buf;

			ptls_buffer_init(&buf, "", 0);

            ret = ptls_get_pem_object(F, label, &buf, log_file);

            if (ret == 0)
            {
                if (buf.off > 0 && buf.is_allocated)
                {
                    list[count]->base = buf.base;
                    list[count]->len = buf.off;
                    count++;
                }
				else
				{
					ptls_buffer_dispose(&buf);
				}
            }
            else
            {
                ptls_buffer_dispose(&buf);
                break;
            }
        }
    }
    
    if (ret == PTLS_ERROR_PEM_LABEL_NOT_FOUND && count > 0)
    {
        ret = 0;
    }

    *nb_objects = count;

    if (F != NULL)
    {
        fclose(F);
    }

    return ret;
}

int ptls_pem_get_certificates(char const * pem_fname, ptls_iovec_t ** list, size_t list_max, 
	size_t * nb_certs, FILE * log_file)
{
    return ptls_pem_get_objects(pem_fname, "CERTIFICATE", list, list_max, nb_certs, log_file);
}


struct ptls_asn1_pkcs8_private_key {
	ptls_iovec_t vec;
	size_t algorithm_index;
	uint32_t algorithm_length;
	size_t parameters_index;
	uint32_t parameters_length;
	size_t key_data_index;
	uint32_t key_data_length;
};

int ptls_pem_parse_private_key(char const * pem_fname, 
	struct ptls_asn1_pkcs8_private_key * pkey, FILE * log_file)
{
	size_t nb_keys = 0;
	ptls_iovec_t * list = &pkey->vec;
	int ret = ptls_pem_get_objects(pem_fname, "PRIVATE KEY", &list, 1, &nb_keys, NULL);

	if (ret == 0)
	{
		if (nb_keys != 1)
		{
			ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
		}
	}

	if (ret == 0 && nb_keys == 1)
	{
		/* read the ASN1 messages */
		size_t byte_index = 0;
		uint8_t * bytes = pkey->vec.base;
		size_t bytes_max = pkey->vec.len;
		int decode_error = 0;
		uint32_t seq0_length = 0;
		size_t last_byte0;
		uint32_t seq1_length = 0;
		size_t last_byte1 = 0;
		uint32_t oid_length;
		size_t last_oid_byte;
		uint32_t key_data_length;
		size_t key_data_last;


		if (log_file != NULL)
		{
			fprintf(log_file, "\nFound PRIVATE KEY, length = %d bytes\n", (int)bytes_max);
		}

		/* start with sequence */
		byte_index = ptls_asn1_get_expected_type_and_length(
			bytes, bytes_max, byte_index, 0x30,
			&seq0_length, NULL, &last_byte0, &decode_error, log_file);

		if (decode_error == 0 && bytes_max != last_byte0)
		{
			byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index,
				&decode_error, 0, log_file);
			decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
		}

		if (decode_error == 0)
		{
			/* get first component: version, INTEGER, expect value 0 */
			if (byte_index + 3 > bytes_max)
			{
				byte_index = ptls_asn1_error_message("Incorrect length for DER", bytes_max, byte_index,
					&decode_error, 0, log_file);
				decode_error = PTLS_ERROR_INCORRECT_PEM_SYNTAX;
			}
			else if (bytes[byte_index] != 0x02 ||
				bytes[byte_index + 1] != 0x01 ||
				bytes[byte_index + 2] != 0x00)
			{
				decode_error = PTLS_ERROR_INCORRECT_PEM_KEY_VERSION;
				byte_index = ptls_asn1_error_message("Incorrect PEM Version", bytes_max, byte_index,
					&decode_error, 0, log_file);
			}
			else
			{
				byte_index += 3;
				if (log_file != NULL)
				{
					fprintf(log_file, "   Version = 1,\n");
				}
			}
		}

		if (decode_error == 0)
		{
			/* open embedded sequence */
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, bytes_max, byte_index, 0x30,
				&seq1_length, NULL, &last_byte1, &decode_error, log_file);
		}

		if (decode_error == 0)
		{
			if (log_file != NULL)
			{
				fprintf(log_file, "   Algorithm Identifier:\n");
			}
			/* get length of OID */
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, last_byte1, byte_index, 0x06,
				&oid_length, NULL, &last_oid_byte, &decode_error, log_file);

			if (decode_error == 0)
			{
				if (log_file != NULL)
				{
					/* print the OID value */
					fprintf(log_file, "      Algorithm:");
					ptls_asn1_dump_content(bytes + byte_index, oid_length, 0, log_file);
					fprintf(log_file, ",\n");
				}
				pkey->algorithm_index = byte_index;
				pkey->algorithm_length = oid_length;
				byte_index += oid_length;
			}
		}

		if (decode_error == 0)
		{
			/* get parameters, ANY */
			if (log_file != NULL)
			{
				fprintf(log_file, "      Parameters:\n");
			}

			pkey->parameters_index = byte_index;

			pkey->parameters_length = ptls_asn1_validation_recursive(bytes + byte_index,
				last_byte1 - byte_index, &decode_error, 2, log_file);

			byte_index += pkey->parameters_length;
			
			if (log_file != NULL)
			{
				fprintf(log_file, "\n");
			}
			/* close sequence */
			if (byte_index != last_byte1)
			{
				byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index,
					&decode_error, 2, log_file);
				decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
			}
		}

		/* get octet string, key */
		if (decode_error == 0)
		{
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, last_byte0, byte_index, 0x04,
				&key_data_length, NULL, &key_data_last, &decode_error, log_file);

			if (decode_error == 0)
			{
				pkey->key_data_index = byte_index;
				pkey->key_data_length = key_data_length;
				byte_index += key_data_length;

				if (log_file != NULL)
				{
					fprintf(log_file, "   Key data (%d bytes):\n", key_data_length);

					(void) ptls_asn1_validation_recursive(bytes + pkey->key_data_index,
						key_data_length, &decode_error, 1, log_file);
					fprintf(log_file, "\n");
				}
			}
		}
		if (decode_error == 0 && byte_index != last_byte0)
		{
			byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index,
				&decode_error, 0, log_file);
			decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
		}

		if (decode_error != 0)
		{
			ret = decode_error;
		}
	}
	return ret;
}

const uint8_t ptls_asn1_algorithm_ecdsa[] = { 
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

const uint8_t ptls_asn1_curve_secp512r1[] = {
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};


int ptls_set_ecdsa_private_key(ptls_context_t * ctx,
	struct ptls_asn1_pkcs8_private_key * pkey, FILE * log_file)
{
	uint8_t * bytes = pkey->vec.base + pkey->parameters_index;
	size_t bytes_max = pkey->parameters_length;
	size_t byte_index = 0;
	uint8_t * curve_id = NULL;
	uint32_t curve_id_length = 0;
	int decode_error = 0;
	uint32_t seq_length;
	size_t last_byte = 0;
	uint8_t * ecdsa_key_data = NULL;
	uint32_t ecdsa_key_data_length = 0;
	size_t  ecdsa_key_data_last = 0;

	/* We expect the parameters to include just the curve ID */

	byte_index = ptls_asn1_get_expected_type_and_length(
		bytes, bytes_max, byte_index, 0x06,
		&curve_id_length, NULL, &last_byte, &decode_error, log_file);

	if (decode_error == 0 && bytes_max != last_byte)
	{
		byte_index = ptls_asn1_error_message("Length larger than parameters", bytes_max, byte_index,
			&decode_error, 0, log_file);
		decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
	}

	if (decode_error == 0)
	{
		curve_id = bytes + byte_index;

		if (log_file != NULL)
		{
			/* print the OID value */
			fprintf(log_file, "Curve: ");
			ptls_asn1_dump_content(curve_id, curve_id_length, 0, log_file);
			fprintf(log_file, "\n");
		}
	}

	/* We expect the key data to follow the ECDSA structure per RFC 5915 */
	bytes = pkey->vec.base + pkey->key_data_index;
	bytes_max = pkey->key_data_length;
	byte_index = 0;

	/* decode the wrapping sequence */
	if (decode_error == 0)
	{
		byte_index = ptls_asn1_get_expected_type_and_length(
			bytes, bytes_max, byte_index, 0x30,
			&seq_length, NULL, &last_byte, &decode_error, log_file);
	}

	if (decode_error == 0 && bytes_max != last_byte)
	{
		byte_index = ptls_asn1_error_message("Length larger than key data", bytes_max, byte_index,
			&decode_error, 0, log_file);
		decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
	}

	/* verify and skip the version number 1 */
	if (decode_error == 0)
	{
		/* get first component: version, INTEGER, expect value 0 */
		if (byte_index + 3 > bytes_max)
		{
			byte_index = ptls_asn1_error_message("Incorrect length for DER", bytes_max, byte_index,
				&decode_error, 0, log_file);
			decode_error = PTLS_ERROR_INCORRECT_PEM_SYNTAX;
		}
		else if (bytes[byte_index] != 0x02 ||
			bytes[byte_index + 1] != 0x01 ||
			bytes[byte_index + 2] != 0x01)
		{
			decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_KEY_VERSION;
			byte_index = ptls_asn1_error_message("Incorrect ECDSA Key Data Version", bytes_max, byte_index,
				&decode_error, 0, log_file);
		}
		else
		{
			byte_index += 3;
			if (log_file != NULL)
			{
				fprintf(log_file, "ECDSA Version = 1,\n");
			}
		}
	}

	/* obtain the octet string that contains the ECDSA private key */
	if (decode_error == 0)
	{
		byte_index = ptls_asn1_get_expected_type_and_length(
			bytes, last_byte, byte_index, 0x04,
			&ecdsa_key_data_length, NULL, &ecdsa_key_data_last, &decode_error, log_file);

		if (decode_error == 0)
		{
			ecdsa_key_data = bytes + byte_index;
		}
	}

	/* If everything is fine, associate the ECDSA key with the context */
	if (curve_id_length == sizeof(ptls_asn1_curve_secp512r1) && curve_id != NULL &&
		memcmp(curve_id, ptls_asn1_curve_secp512r1, sizeof(ptls_asn1_curve_secp512r1)) == 0)
	{
		if (SECP256R1_PRIVATE_KEY_SIZE != ecdsa_key_data_length)
		{
			decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_KEYSIZE;
			if (log_file != NULL)
			{
				/* print the OID value */
				fprintf(log_file, "Wrong SECP256R1 key length, %d instead of %d.\n",
					ecdsa_key_data_length, SECP256R1_PRIVATE_KEY_SIZE);
			}
		}
		else
		{
			ptls_minicrypto_secp256r1sha256_sign_certificate_t * minicrypto_sign_certificate;

			minicrypto_sign_certificate =
				(ptls_minicrypto_secp256r1sha256_sign_certificate_t *)malloc(
					sizeof(ptls_minicrypto_secp256r1sha256_sign_certificate_t));

			if (minicrypto_sign_certificate == NULL)
			{
				decode_error = PTLS_ERROR_NO_MEMORY;
			}
			else
			{
				memset(minicrypto_sign_certificate, 0, 
					sizeof(ptls_minicrypto_secp256r1sha256_sign_certificate_t));
				decode_error = ptls_minicrypto_init_secp256r1sha256_sign_certificate(
					minicrypto_sign_certificate, ptls_iovec_init(ecdsa_key_data, ecdsa_key_data_length));
			}
			if (decode_error == 0)
			{
				ctx->sign_certificate = &minicrypto_sign_certificate->super;

				if (log_file != NULL)
				{
					/* print the OID value */
					fprintf(log_file, "Initialized SECP512R1 signing key with %d bytes.\n",
						ecdsa_key_data_length);
				}
			}
			else if (log_file != NULL)
			{
				fprintf(log_file, "SECP512R1 init with %d bytes returns %d.\n", ecdsa_key_data_length, decode_error);
			}
		}
	}
	else
	{
		decode_error = PTLS_ERROR_INCORRECT_PEM_ECDSA_CURVE;
		if (log_file != NULL)
		{
			/* print the OID value */
			fprintf(log_file, "Curve is not supported for signatures.\n");
		}
	}

	return decode_error;
}

int ptls_set_private_key(ptls_context_t * ctx, char const * pem_fname, FILE * log_file)
{
	struct ptls_asn1_pkcs8_private_key pkey = { {0} };
	int ret = ptls_pem_parse_private_key(pem_fname, &pkey, log_file);

	/* Check that this is the expected key type.
	 * At this point, the minicrypto library only supports ECDSA keys.
	 * In theory, we could add support for RSA keys at some point.
	 */
	if (ret == 0)
	{
		if (pkey.algorithm_length == sizeof(ptls_asn1_algorithm_ecdsa) &&
			memcmp(pkey.vec.base + pkey.algorithm_index,
				ptls_asn1_algorithm_ecdsa, sizeof(ptls_asn1_algorithm_ecdsa)) == 0)
		{
			ret = ptls_set_ecdsa_private_key(ctx, &pkey, log_file);
		}
		else
		{
			ret = -1;
		}
	}

	return ret;
}

int ptls_pem_get_private_key(char const * pem_fname, ptls_iovec_t * vec, 
	FILE * log_file)
{
	size_t nb_keys = 0;
	int ret = ptls_pem_get_objects(pem_fname, "PRIVATE KEY", &vec, 1, &nb_keys, NULL);

	if (ret == 0)
	{
		if (nb_keys != 1)
		{
			ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
		}
	}
	if (ret == 0 && nb_keys == 1)
	{
		/* read the ASN1 messages */
		size_t byte_index = 0;
		uint8_t * bytes = vec->base;
		size_t bytes_max = vec->len;
		int decode_error = 0;
		uint32_t seq0_length = 0;
		size_t last_byte0;
		uint32_t seq1_length = 0;
		size_t last_byte1 = 0;
		uint32_t oid_length;
		size_t last_oid_byte;
		uint32_t key_data_length;
		size_t key_data_last;


		if (log_file != NULL)
		{
			fprintf(log_file, "\nFound PRIVATE KEY, length = %d bytes\n", (int)bytes_max);
		}

		/* start with sequence */
		byte_index = ptls_asn1_get_expected_type_and_length(
			bytes, bytes_max, byte_index, 0x30,
			&seq0_length, NULL, &last_byte0, &decode_error, log_file);

		if (decode_error == 0 && bytes_max != last_byte0)
		{
			byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index,
					&decode_error, 0, log_file);
			decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
		}

		if (decode_error == 0)
		{
			/* get first component: version, INTEGER, expect value 0 */
			if (byte_index + 3 > bytes_max)
			{
				byte_index = ptls_asn1_error_message("Incorrect length for DER", bytes_max, byte_index,
					&decode_error, 0, log_file);
				decode_error = PTLS_ERROR_INCORRECT_PEM_SYNTAX;
			}
			else if (bytes[byte_index] != 0x02 ||
				bytes[byte_index + 1] != 0x01 ||
				bytes[byte_index + 2] != 0x00)
			{
				decode_error = PTLS_ERROR_INCORRECT_PEM_KEY_VERSION;
				byte_index = ptls_asn1_error_message("Incorrect PEM Version", bytes_max, byte_index,
					&decode_error, 0, log_file);
			}
			else
			{
				byte_index += 3; 
				if (log_file != NULL)
				{
					fprintf(log_file, "   Version = 1,\n");
				}
			}
		}

		if (decode_error == 0)
		{
			/* open embedded sequence */
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, bytes_max, byte_index, 0x30,
				&seq1_length, NULL, &last_byte1, &decode_error, log_file);
		}

		if (decode_error == 0)
		{
			if (log_file != NULL)
			{
				fprintf(log_file, "   Algorithm Identifier:\n");
			}
			/* get length of OID */
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, last_byte1, byte_index, 0x06,
				&oid_length, NULL, &last_oid_byte, &decode_error, log_file);
			
			if (decode_error == 0)
			{
				if (log_file != NULL)
				{
					/* print the OID value */
					fprintf(log_file, "      Algorithm:");
					ptls_asn1_dump_content(bytes + byte_index, oid_length, 0, log_file);
					fprintf(log_file, ",\n");
				}
				byte_index += oid_length;
			}
		}

		if (decode_error == 0)
		{
			/* get parameters, ANY */
			if (log_file != NULL)
			{
				fprintf(log_file, "      Parameters:\n");
			}
			byte_index += ptls_asn1_validation_recursive(bytes + byte_index, 
				last_byte1 - byte_index, &decode_error, 2, log_file);
			if (log_file != NULL)
			{
				fprintf(log_file, "\n");
			}
			/* close sequence */
			if (byte_index != last_byte1)
			{
				byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index,
					&decode_error, 2, log_file);
				decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
			}
		}

		/* get octet string, key */
		if (decode_error == 0)
		{
			byte_index = ptls_asn1_get_expected_type_and_length(
				bytes, bytes_max, byte_index, 0x04,
				&key_data_length, NULL, &key_data_last, &decode_error, log_file);

			if (decode_error == 0)
			{
				if (log_file != NULL)
				{
					fprintf(log_file, "   Key data (%d bytes):\n", key_data_length);
				}
				/* print octet string as ASN.1 component */
				if (byte_index != last_byte1)
				{
					byte_index += ptls_asn1_validation_recursive(bytes + byte_index,
						key_data_length, &decode_error, 1, log_file);
					if (log_file != NULL)
					{
						fprintf(log_file, "\n");
					}
				}
			}
		}
		if (decode_error == 0 && byte_index != last_byte0)
		{
			byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index,
				&decode_error, 0, log_file);
			decode_error = PTLS_ERROR_INCORRECT_BER_ENCODING;
		}

		if (decode_error != 0)
		{
			ret = decode_error;
		}
	}
	return ret;
}

/*
IMO it could be implemented in either of the three ways :

a) a function that accepts `ptls_context_t *` and a filename as
arguments.The function will populate `ptls_context_t::certificates`.
A function that disposes of the memory allocated for the certificates
stored in the context needs to be defined as well.
b) a function that accepts `ptls_context_t *` and `FILE *` as
arguments.The function will populate `ptls_context_t::certificates`.
A function that disposes of the memory allocated for the certificates
stored in the context needs to be defined as well.
c) a function that accepts `FILE *` and returns at most one
certificate(in type ptls_iovec_t, with `ptls_iovec_t::base` being
    allocated using malloc).User should call the function repeatedly
    until it returns an EOF.It is the users' responsibility to setup
    `ptls_context_t::certificates` by using the values returned the
    function.

    I do not have a strong preference between the three, though it might
    make sense to implement(c) and optionally provide a wrapper in the
    style of either(a) or (b).
*/
#define PTLS_MAX_CERTS_IN_CONTEXT 16

int ptls_set_context_certificates(ptls_context_t * ctx, 
    char * cert_pem_file, FILE* log_file)
{
    int ret = 0;

    ctx->certificates.list = (ptls_iovec_t *)
        malloc(PTLS_MAX_CERTS_IN_CONTEXT * sizeof(ptls_iovec_t));

    if (ctx->certificates.list == NULL)
    {
        ret = PTLS_ERROR_NO_MEMORY;
    }
    else
    {
        ret = ptls_pem_get_objects(cert_pem_file, "CERTIFICATE",
            &ctx->certificates.list, PTLS_MAX_CERTS_IN_CONTEXT, &ctx->certificates.count, log_file);
    }

    return ret;
}


/*
> 2) What is the proper API to push signing keys in mini crypto.

IMO it should either be :

a) a function that initializes
`ptls_minicrypto_secp256r1sha256_sign_certificate_t` (much like
    ptls_minicrypto_init_secp256r1sha256_sign_certificate), taking address
    of the object and a filename of the private key as arguments
    b) a function that initializes
    `ptls_minicrypto_secp256r1sha256_sign_certificate_t` (much like
        ptls_minicrypto_init_secp256r1sha256_sign_certificate), taking address
    of the object and `FILE *` of the private key as arguments
    c) a function that reads a private key from file(either specified by
    a filename or a file pointer) and returns it as `ptls_iovec_t`

    For the matter, I think that having(c), as well as optionally having
    either(a) or (b)might make sense.
*/

