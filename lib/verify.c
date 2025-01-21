/*
 * Copyright (c) 2025 DeNA Co., Ltd., Kazuho Oku et al.
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
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include "picotls.h"
#include "uECC.h"
#include "ecc.h"
#include "sha2.h"
#include "picotls.h"
#include "asn1.h"


/* Certificate validation uses UTC for time comparisons */
typedef struct  {
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
} ptls_minicrypto_datetime_t;

static inline void datetime_utc(ptls_minicrypto_datetime_t *now)
{
    time_t unixtime;
    time(&unixtime);
    struct tm brokendown;
    gmtime_r(&unixtime, &brokendown);
    now->year = brokendown.tm_year + 1900;
    now->month = brokendown.tm_mon + 1;
    now->day = brokendown.tm_mday;
    now->hour = brokendown.tm_hour;
    now->minute = brokendown.tm_min;
    now->second = brokendown.tm_sec;
}


/* Parse DER with ASN.1 */

#define ASN1_BOOLEAN                 0x01
#define ASN1_INTEGER                 0x02
#define ASN1_BIT_STRING              0x03
#define ASN1_OCTET_STRING            0x04
#define ASN1_NULL                    0x05
#define ASN1_OID                     0x06
#define ASN1_ENUMERATED              0x0A
#define ASN1_UTF8_STRING             0x0C
#define ASN1_SEQUENCE                0x10
#define ASN1_SET                     0x11
#define ASN1_PRINTABLE_STRING        0x13
#define ASN1_T61_STRING              0x14
#define ASN1_IA5_STRING              0x16
#define ASN1_UTC_TIME                0x17
#define ASN1_GENERALIZED_TIME        0x18
#define ASN1_UNIVERSAL_STRING        0x1C
#define ASN1_BMP_STRING              0x1E
#define ASN1_CONSTRUCTED             0x20
#define ASN1_CONTEXT_SPECIFIC        0x80

static int parse_der_trim_integer(const uint8_t *data, size_t *index, uint32_t *length)
{
    /* It's invalid to have:
     * - length == 0
     * - most significant bit without a leading 0x00 */
    if ((*length == 0 || (data[*index] & 0x80) != 0)) {
        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
    }
    /* Skip possible leading zero */
    if (data[*index] == 0x00) {
        *index += 1;
        *length -= 1;
        /* It is not allowed to have more than 1 leading zero */
        if (*length == 0 || (data[*index] == 0x00)) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
    }
    return 0;
}
static int parse_der_trim_bitstring(const uint8_t *data, size_t *index, uint32_t *length)
{
    uint8_t unused_bits;
    /* Empty bitstring is not an ASN1 error condition */
    if (*length == 0) {
        return 0;
    }
    unused_bits = data[*index];
    if (unused_bits > 7) {
        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
    }
    *index += 1;
    *length -= 1;
    return 0;
}

#define MAX_ENTRIES_BUFFER      16
typedef struct {
    const uint8_t *oid_offset;
    uint32_t oid_length;
    const uint8_t *val_offset;
    uint32_t val_length;
} ptls_minicrypto_oidset_entry_t;

typedef struct {
    ptls_minicrypto_oidset_entry_t *entries;
    uint32_t entries_length;
    ptls_minicrypto_oidset_entry_t buffer[MAX_ENTRIES_BUFFER];   /* avoid malloc */
} ptls_minicrypto_oidset_t;

static int parse_der_oidset(const uint8_t *buf, size_t buflen, ptls_minicrypto_oidset_t *oidset)
{
    size_t iterator_lastbyte;
    oidset->entries = oidset->buffer;
    oidset->entries_length = 0;

    for(iterator_lastbyte=0; iterator_lastbyte < buflen;) {
        int decode_error = 0;
        size_t index, lastbyte;
        uint32_t length;
        int structure_bit, type_class;
        uint32_t type_number;
        ptls_minicrypto_oidset_entry_t *oidset_entry;

        index = ptls_asn1_get_expected_type_and_length(buf, buflen, iterator_lastbyte, ASN1_CONSTRUCTED|ASN1_SET, &length, NULL, &iterator_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }

        index = ptls_asn1_get_expected_type_and_length(buf, buflen, index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (lastbyte != iterator_lastbyte) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        /* create slot */
        if (oidset->entries != oidset->buffer) {
            size_t entry_length = sizeof(oidset->entries[0]) * (oidset->entries_length + 1);
            oidset->entries = realloc(oidset->entries, entry_length);
        }
        else if (oidset->entries_length == MAX_ENTRIES_BUFFER) {
            size_t i;
            oidset->entries = malloc(sizeof(oidset->entries[0]) * (oidset->entries_length + 1));
            for (i=0; i < oidset->entries_length; ++i) {
                oidset->entries[i] = oidset->buffer[i];
            }
        }
        oidset_entry = &oidset->entries[oidset->entries_length];
        oidset->entries_length += 1;

        /* oid-key */
        index = ptls_asn1_get_expected_type_and_length(buf, buflen, index, ASN1_OID, &length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        oidset_entry->oid_offset = buf + index;
        oidset_entry->oid_length = length;

        /* set-val */
        ptls_asn1_read_type(buf + lastbyte, buflen - lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (structure_bit != 0 || type_class != 0) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        if (type_number != ASN1_BMP_STRING && type_number != ASN1_UTF8_STRING      && type_number != ASN1_T61_STRING && type_number != ASN1_PRINTABLE_STRING &&
            type_number != ASN1_IA5_STRING && type_number != ASN1_UNIVERSAL_STRING && type_number != ASN1_BIT_STRING) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        index = ptls_asn1_get_expected_type_and_length(buf, buflen, lastbyte, type_number, &length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (lastbyte != iterator_lastbyte) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        oidset_entry->val_offset = buf + index;
        oidset_entry->val_length = length;
    }
    if (iterator_lastbyte != buflen) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    return 0;
}

#define X509_EXT_BASIC_CONSTRAINTS          1
#define X509_EXT_KEY_USAGE                  2
#define X509_EXT_EXTENDED_KEY_USAGE         3
#define X509_EXT_ANY_EXTENDED_KEY_USAGE     4
#define X509_EXT_SUBJECT_ALT_NAME           5
#define X509_EXT_NS_CERT_TYPE               6
#define X509_EXT_CERTIFICATE_POLICIES       7
#define X509_EXT_SUBJECT_KEY_IDENTIFIER     8
#define X509_EXT_AUTHORITY_KEY_IDENTIFIER   9
#define X509_EXT_ANY_POLICY                 10

#define X509_SAN_OTHER_NAME                     0
#define X509_SAN_RFC822_NAME                    1
#define X509_SAN_DNS_NAME                       2
#define X509_SAN_X400_ADDRESS_NAME              3
#define X509_SAN_DIRECTORY_NAME                 4
#define X509_SAN_EDI_PARTY_NAME                 5
#define X509_SAN_UNIFORM_RESOURCE_IDENTIFIER    6
#define X509_SAN_IP_ADDRESS                     7
#define X509_SAN_REGISTERED_ID                  8

typedef struct {
    uint64_t type;
    const uint8_t *offset;
    uint32_t length;
} ptls_minicrypto_altname_entry_t;
typedef struct {
    ptls_minicrypto_altname_entry_t *entries;
    uint32_t entries_length;
    ptls_minicrypto_altname_entry_t buffer[MAX_ENTRIES_BUFFER];   /* avoid malloc */
} ptls_minicrypto_altname_t;

static int parse_der_subject_alt_name(const uint8_t *buf, size_t buflen, ptls_minicrypto_altname_t *subject_alt_name)
{
    size_t iterator_lastbyte;
    subject_alt_name->entries = subject_alt_name->buffer;
    subject_alt_name->entries_length = 0;

    for(iterator_lastbyte=0; iterator_lastbyte < buflen;) {
        int decode_error = 0;
        size_t name_index;
        uint32_t name_length;
        int structure_bit, type_class;
        uint32_t type_number;
        ptls_minicrypto_altname_entry_t entry;

        ptls_asn1_read_type(buf + iterator_lastbyte, buflen - iterator_lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (type_class == 0) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        name_index = ptls_asn1_get_expected_type_and_length(buf, buflen, iterator_lastbyte, ASN1_CONTEXT_SPECIFIC|(structure_bit?ASN1_CONSTRUCTED:0)|type_number, &name_length, NULL, &iterator_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }

        /* GeneralName ::= CHOICE {
         *    otherName	[0] INSTANCE OF OTHER-NAME,
         *    rfc822Name	    IA5String,
         *    dNSName		    IA5String,
         *    x400Address	    ORAddress,
         *    directoryName	    Name,
         *    ediPartyName	    EDIPartyName,
         *    uniformResourceIdentifier  IA5String,
         *    IPAddress	        OCTET STRING,
         *    registeredID	    OBJECT IDENTIFIER
        */
        entry.type = type_number;
        if (type_number == X509_SAN_OTHER_NAME) {
            continue;   /* unsupported SAN */
        }
        else if (type_number == X509_SAN_RFC822_NAME) {
            entry.offset = buf + name_index;
            entry.length = name_length;
        }
        else if (type_number == X509_SAN_DNS_NAME) {
            entry.offset = buf + name_index;
            entry.length = name_length;
        }
        else if (type_number == X509_SAN_X400_ADDRESS_NAME) {
            continue;   /* unsupported SAN */
        }
        else if (type_number == X509_SAN_DIRECTORY_NAME) {
            continue;   /* unsupported SAN */
        }
        else if (type_number == X509_SAN_EDI_PARTY_NAME) {
            continue;   /* unsupported SAN */
        }
        else if (type_number == X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) {
            entry.offset = buf + name_index;
            entry.length = name_length;
        }
        else if (type_number == X509_SAN_IP_ADDRESS) {
            if (name_length != 4 && name_length != 16) {
                continue;   /* unsupported SAN */
            }
            entry.offset = buf + name_index;
            entry.length = name_length;
        }
        else if (type_number == X509_SAN_REGISTERED_ID) {
            continue;   /* unsupported SAN */
        }
        else {
            continue;   /* unsupported SAN */
        }

        /* create slot */
        if (subject_alt_name->entries != subject_alt_name->buffer) {
            size_t entry_length = sizeof(subject_alt_name->entries[0]) * (subject_alt_name->entries_length + 1);
            subject_alt_name->entries = realloc(subject_alt_name->entries, entry_length);
        }
        else if (subject_alt_name->entries_length == MAX_ENTRIES_BUFFER) {
            size_t i;
            subject_alt_name->entries = malloc(sizeof(subject_alt_name->entries[0]) * (subject_alt_name->entries_length + 1));
            for (i=0; i < subject_alt_name->entries_length; ++i) {
                subject_alt_name->entries[i] = subject_alt_name->buffer[i];
            }
        }
        subject_alt_name->entries[subject_alt_name->entries_length] = entry;
        subject_alt_name->entries_length += 1;
    }
    if (iterator_lastbyte != buflen) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    if (subject_alt_name->entries_length == 0) {
        return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
    }
    return 0;
}

#define PUBLIC_KEY_RSA                      1
#define PUBLIC_KEY_EC                       2
#define PUBLIC_KEY_EC_DH                    3

#define EC_GROUP_SECP192R1                  1
#define EC_GROUP_SECP224R1                  2
#define EC_GROUP_SECP256R1                  3
#define EC_GROUP_SECP384R1                  4
#define EC_GROUP_SECP521R1                  5
#define EC_GROUP_SECP192K1                  6
#define EC_GROUP_SECP224K1                  7
#define EC_GROUP_SECP256K1                  8
#define EC_GROUP_BP256R1                    9
#define EC_GROUP_BP384R1                    10
#define EC_GROUP_BP512R1                    11

typedef struct ptls_minicrypto_certificate_s {
    ptls_iovec_t raw_der;

    /* parsed */
    ptls_iovec_t tbs_der;
    uint64_t version;

    ptls_minicrypto_oidset_t subject;
    ptls_minicrypto_altname_t subject_alt_name;
    int v3_subject_alternative_name;
    ptls_minicrypto_oidset_t issuer;

    ptls_minicrypto_datetime_t validity_notBefore;
    ptls_minicrypto_datetime_t validity_notAfter;

    int is_CA;
    uint64_t max_pathlen;
    uint8_t keyusage_digital_signature;
    uint8_t keyusage_non_repudiation;
    uint8_t keyusage_key_encipherment;
    uint8_t keyusage_data_encipherment;
    uint8_t keyusage_key_agreement;
    uint8_t keyusage_key_cert_sign;
    uint8_t keyusage_crl_sign;
    uint8_t keyusage_encipher_only;
    uint8_t keyusage_decipher_only;

    uint64_t publickey_type;
    ptls_iovec_t publickey;
    uint64_t ec_group;

    uint64_t signature_algorithm;
    ptls_iovec_t signature;

    /* chain */
    const struct ptls_minicrypto_certificate_s *next;
} ptls_minicrypto_certificate_t;

static void free_certchain(const ptls_minicrypto_certificate_t *cert)
{
    while (cert != NULL ) {
        const ptls_minicrypto_certificate_t *next = cert->next;
        if (cert->subject.entries != cert->subject.buffer) {
            free(cert->subject.entries);
        }
        if (cert->subject_alt_name.entries != cert->subject_alt_name.buffer) {
            free(cert->subject_alt_name.entries);
        }
        if (cert->issuer.entries != cert->issuer.buffer) {
            free(cert->issuer.entries);
        }
        free((void*)cert);
        cert = next;
    }
}

static int parse_der_certificate(ptls_minicrypto_certificate_t *cert, uint8_t *cert_raw, size_t cert_raw_len)
{
    int decode_error = 0;
    size_t lastbyte, certifcate_index, tbsCertificate_index, signatureAlgorithm_index, signatureValue_index;
    uint32_t certifcate_length, tbsCertificate_length, signatureAlgorithm_length, signatureValue_length;
    size_t tbsCertificate_oid_index = 0;
    uint32_t tbsCertificate_oid_length = 0;

    /* raw */
    cert->raw_der.base = cert_raw;
    cert->raw_der.len = cert_raw_len;

    /* https://datatracker.ietf.org/doc/html/rfc5912 */
    certifcate_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, 0, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &certifcate_length, NULL, &lastbyte, &decode_error, NULL);
    if (decode_error != 0) {
        return decode_error;
    }
    if (lastbyte != cert_raw_len) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /* TBSCertificate */
    tbsCertificate_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, certifcate_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbsCertificate_length, NULL, &lastbyte, &decode_error, NULL);
    if (decode_error != 0) {
        return decode_error;
    }
    /* signatureAlgorithm */
    signatureAlgorithm_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &signatureAlgorithm_length, NULL, &lastbyte, &decode_error, NULL);
    if (decode_error != 0) {
        return decode_error;
    }
    /* signatureValue */
    signatureValue_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_BIT_STRING, &signatureValue_length, NULL, &lastbyte, &decode_error, NULL);
    if (decode_error != 0) {
        return decode_error;
    }
    if (lastbyte != cert_raw_len) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /*
    TBSCertificate  ::=  SEQUENCE  {
        version         [0]  Version DEFAULT v1,
        serialNumber         CertificateSerialNumber,
        signature            AlgorithmIdentifier,
        issuer               Name,
        validity             Validity,
        subject              Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        ... ,
        [[2:               -- If present, version MUST be v2
        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL
        ]],
        [[3:               -- If present, version MUST be v3 --
        extensions      [3]  Extensions{{CertExtensions}} OPTIONAL
        ]], ...
    */
    if (tbsCertificate_length != 0) {
        size_t i, j, tbscert_index;
        uint32_t tbscert_length;

        cert->tbs_der.base = cert_raw + certifcate_index;
        cert->tbs_der.len = (tbsCertificate_index - certifcate_index) + tbsCertificate_length;

        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbsCertificate_index, ASN1_CONTEXT_SPECIFIC|ASN1_CONSTRUCTED, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }

        /* version */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbscert_index, ASN1_INTEGER, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (tbscert_length != 1) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
        cert->version = cert_raw[tbscert_index] + 1;
        if (cert->version < 1 || cert->version > 3) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        /* serialNumber */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_INTEGER, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }

        /* signature */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (tbscert_length != 0) {
            size_t oid_lastbyte;
            uint32_t oid_length;
            size_t oid_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbscert_index, ASN1_OID, &oid_length, NULL, &oid_lastbyte, &decode_error, NULL);
            if (decode_error != 0) {
                return decode_error;
            }
            /*if (oid_lastbyte != tbscert_index + tbscert_length) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }*/
            tbsCertificate_oid_index = oid_index;
            tbsCertificate_oid_length = oid_length;
        }
        else {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        /* issuer */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (tbscert_length != 0) {
            int status = parse_der_oidset(cert_raw + tbscert_index, tbscert_length, &cert->issuer);
            if (status != 0) {
                return status;
            }
        }

        /* validity */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        for (i=0; i < 2 && tbscert_index < lastbyte; ++i) {
            int structure_bit, type_class;
            size_t datetime_index, datetime_lastbyte;
            uint32_t type_number, datetime_length;
            uint32_t numbers[7];
            size_t year_length;

            /* Validity ::= SEQUENCE {
             *      notBefore      Time,
             *      notAfter       Time }
             */
            ptls_asn1_read_type(cert_raw + tbscert_index, cert_raw_len - tbscert_index, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
            if (decode_error != 0) {
                return decode_error;
            }
            if (structure_bit != 0 || type_class != 0) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }
            /* length = 12 or 14 plus optional 'Z' */
            if (type_number == ASN1_UTC_TIME) {
                year_length = 2;
            }
            else if (type_number == ASN1_GENERALIZED_TIME) {
                year_length = 4;
            }
            else {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            datetime_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbscert_index, type_number, &datetime_length, NULL, &datetime_lastbyte, &decode_error, NULL);
            if (decode_error != 0) {
                return decode_error;
            }
            if (datetime_length != year_length + 10 && (datetime_length != year_length + 11 || cert_raw[datetime_index + datetime_length - 1] != 'Z')) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            for (j=0; j < (year_length == 4 ? 7 : 6); ++j) {
                uint8_t dec1 = cert_raw[datetime_index + j*2],
                        dec2 = cert_raw[datetime_index + j*2 + 1];
                if (dec1 < '0' || '9' < dec1 || dec2 < '0' || '9' < dec2) {
                    return PTLS_ALERT_BAD_CERTIFICATE;
                }
                numbers[j] = (dec1 - '0') * 10 + (dec2 - '0');
            }
            ptls_minicrypto_datetime_t *validity = i == 0 ? &cert->validity_notBefore : &cert->validity_notAfter;
            validity->year = year_length == 4 ? numbers[0] * 100 + numbers[1] : (numbers[0] + (numbers[0] < 50 ? 2000 : 1900));
            validity->month  = numbers[year_length == 4 ? 2 : 1];
            validity->day  = numbers[year_length == 4 ? 3 : 2];
            validity->hour = numbers[year_length == 4 ? 4 : 3];
            validity->minute  = numbers[year_length == 4 ? 5 : 4];
            validity->second  = numbers[year_length == 4 ? 6 : 5];

            tbscert_index = datetime_lastbyte;
        }

        /* subject */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (tbscert_length != 0) {
            int status = parse_der_oidset(cert_raw + tbscert_index, tbscert_length, &cert->subject);
            if (status != 0) {
                return status;
            }
        }

        /* subjectPublicKeyInfo */
        tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (tbscert_length != 0) {
            size_t algorithm_lastbyte, pubkeyinfo_lastbyte;
            size_t algorithm_index, publickey_index;
            uint32_t algorithm_length, publickey_length;
            size_t oid_index = 0, params_index = 0;
            uint32_t oid_length = 0, params_length = 0;

            algorithm_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbscert_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &algorithm_length, NULL, &algorithm_lastbyte, &decode_error, NULL);
            if (decode_error != 0) {
                return decode_error;
            }
            if (algorithm_length != 0) {
                size_t oid_lastbyte;
                oid_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, algorithm_index, ASN1_OID, &oid_length, NULL, &oid_lastbyte, &decode_error, NULL);
                if (decode_error != 0) {
                    return decode_error;
                }

                /* EC has params, RSA don't */
                if (oid_lastbyte != algorithm_index + algorithm_length) {
                    int structure_bit, type_class;
                    uint32_t type_number;
                    ptls_asn1_read_type(cert_raw + oid_lastbyte, cert_raw_len - oid_lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
                    if (decode_error != 0) {
                        return decode_error;
                    }
                    if (structure_bit != 0 || type_class != 0) {
                        return PTLS_ALERT_BAD_CERTIFICATE;
                    }
                    params_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, oid_lastbyte, type_number, &params_length, NULL, &oid_lastbyte, &decode_error, NULL);
                    if (decode_error != 0) {
                        return decode_error;
                    }
                    if (oid_lastbyte != algorithm_index + algorithm_length) {
                        return PTLS_ALERT_BAD_CERTIFICATE;
                    }
                }
            }
            else {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            publickey_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, algorithm_lastbyte, ASN1_BIT_STRING, &publickey_length, NULL, &pubkeyinfo_lastbyte, &decode_error, NULL);
            if (decode_error != 0) {
                return decode_error;
            }
            if (pubkeyinfo_lastbyte != tbscert_index + tbscert_length) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            if (publickey_length != 0) {
                static const uint8_t publickey_rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01},
                                     publickey_ec_generic[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01},
                                     publickey_ec_dh[] = {0x2b, 0x81, 0x04, 0x01, 0x0c};

                /* https://datatracker.ietf.org/doc/html/rfc5480#section-2.2 */
                if (oid_length == sizeof(publickey_rsa) && memcmp(cert_raw + oid_index, publickey_rsa, sizeof(publickey_rsa)) == 0) {
                    if (params_length != 0) {
                        return PTLS_ALERT_BAD_CERTIFICATE;
                    }

                    if (parse_der_trim_bitstring(cert_raw, &publickey_index, &publickey_length) != 0) {
                        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                    }
                    cert->publickey_type = PUBLIC_KEY_RSA;
                    cert->publickey.base = cert_raw + publickey_index;
                    cert->publickey.len = publickey_length;
                }
                else if (oid_length == sizeof(publickey_ec_generic) && memcmp(cert_raw + oid_index, publickey_ec_generic, sizeof(publickey_ec_generic)) == 0) {
                    static const uint8_t oid_ec_grp_secp192r1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x01},
                                         oid_ec_grp_secp224r1[] = {0x2b, 0x81, 0x04, 0x00, 0x21},
                                         oid_ec_grp_secp256r1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07},
                                         oid_ec_grp_secp384r1[] = {0x2b, 0x81, 0x04, 0x00, 0x22},
                                         oid_ec_grp_secp521r1[] = {0x2b, 0x81, 0x04, 0x00, 0x23},
                                         oid_ec_grp_secp192k1[] = {0x2b, 0x81, 0x04, 0x00, 0x1f},
                                         oid_ec_grp_secp224k1[] = {0x2b, 0x81, 0x04, 0x00, 0x20},
                                         oid_ec_grp_secp256k1[] = {0x2b, 0x81, 0x04, 0x00, 0x0a},
                                         oid_ec_grp_bp256r1[] = {0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07},
                                         oid_ec_grp_bp384r1[] = {0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b},
                                         oid_ec_grp_bp512r1[] = {0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d};
                    if (params_index == 0 || params_length == 0) {
                        return PTLS_ALERT_BAD_CERTIFICATE;
                    }

                    if (parse_der_trim_bitstring(cert_raw, &publickey_index, &publickey_length) != 0) {
                        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                    }
                    cert->publickey_type = PUBLIC_KEY_EC;
                    cert->publickey.base = cert_raw + publickey_index;
                    cert->publickey.len = publickey_length;

                    /* parse group */
                    if (params_length == sizeof(oid_ec_grp_secp192r1) && memcmp(cert_raw + params_index, oid_ec_grp_secp192r1, sizeof(oid_ec_grp_secp192r1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP192R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp224r1) && memcmp(cert_raw + params_index, oid_ec_grp_secp224r1, sizeof(oid_ec_grp_secp224r1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP224R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp256r1) && memcmp(cert_raw + params_index, oid_ec_grp_secp256r1, sizeof(oid_ec_grp_secp256r1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP256R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp384r1) && memcmp(cert_raw + params_index, oid_ec_grp_secp384r1, sizeof(oid_ec_grp_secp384r1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP384R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp521r1) && memcmp(cert_raw + params_index, oid_ec_grp_secp521r1, sizeof(oid_ec_grp_secp521r1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP521R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp192k1) && memcmp(cert_raw + params_index, oid_ec_grp_secp192k1, sizeof(oid_ec_grp_secp192k1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP192K1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp224k1) && memcmp(cert_raw + params_index, oid_ec_grp_secp224k1, sizeof(oid_ec_grp_secp224k1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP224K1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_secp256k1) && memcmp(cert_raw + params_index, oid_ec_grp_secp256k1, sizeof(oid_ec_grp_secp256k1)) == 0) {
                        cert->ec_group = EC_GROUP_SECP256K1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_bp256r1) && memcmp(cert_raw + params_index, oid_ec_grp_bp256r1, sizeof(oid_ec_grp_bp256r1)) == 0) {
                        cert->ec_group = EC_GROUP_BP256R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_bp384r1) && memcmp(cert_raw + params_index, oid_ec_grp_bp384r1, sizeof(oid_ec_grp_bp384r1)) == 0) {
                        cert->ec_group = EC_GROUP_BP384R1;
                    }
                    else if (params_length == sizeof(oid_ec_grp_bp512r1) && memcmp(cert_raw + params_index, oid_ec_grp_bp512r1, sizeof(oid_ec_grp_bp512r1)) == 0) {
                        cert->ec_group = EC_GROUP_BP512R1;
                    }
                }
                else if (oid_length == sizeof(publickey_ec_dh) && memcmp(cert_raw + oid_index, publickey_ec_dh, sizeof(publickey_ec_dh)) == 0) {
                    cert->publickey_type = PUBLIC_KEY_EC_DH;
                    cert->publickey.base = cert_raw + publickey_index;
                    cert->publickey.len = publickey_length;
                }
                else {
                    return PTLS_ERROR_NOT_AVAILABLE;
                }
            }
            else {
                return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
            }
        }
        else {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }

        /* issuerUniqueID */
        if ((cert->version == 2 || cert->version == 3) && lastbyte != tbsCertificate_index + tbsCertificate_length) {
            int structure_bit, type_class;
            uint32_t type_number;
            ptls_asn1_read_type(cert_raw + lastbyte, cert_raw_len - lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
            if (decode_error != 0) {
                return decode_error;
            }

            if (structure_bit == 1 && type_class == 2 && type_number == 1) {
                tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONTEXT_SPECIFIC|ASN1_CONSTRUCTED|1, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
                if (decode_error != 0) {
                    return decode_error;
                }
            }
        }

        /* subjectUniqueID */
        if ((cert->version == 2 || cert->version == 3) && lastbyte != tbsCertificate_index + tbsCertificate_length) {
            int structure_bit, type_class;
            uint32_t type_number;
            ptls_asn1_read_type(cert_raw + lastbyte, cert_raw_len - lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
            if (decode_error != 0) {
                return decode_error;
            }

            if (structure_bit == 1 && type_class == 2 && type_number == 2) {
                tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONTEXT_SPECIFIC|ASN1_CONSTRUCTED|2, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
                if (decode_error != 0) {
                    return decode_error;
                }
            }
        }

        /* extensions */
        if (cert->version == 3 && lastbyte != tbsCertificate_index + tbsCertificate_length) {
            int structure_bit, type_class;
            uint32_t type_number;
            ptls_asn1_read_type(cert_raw + lastbyte, cert_raw_len - lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
            if (decode_error != 0) {
                return decode_error;
            }

            if (structure_bit == 1 && type_class == 2 && type_number == 3) {
                size_t extension_index, iterator_lastbyte;
                uint32_t extension_length;

                tbscert_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_CONTEXT_SPECIFIC|ASN1_CONSTRUCTED|3, &tbscert_length, NULL, &lastbyte, &decode_error, NULL);
                if (decode_error != 0) {
                    return decode_error;
                }
                if (lastbyte != tbsCertificate_index + tbsCertificate_length) {
                    return PTLS_ALERT_BAD_CERTIFICATE;
                }

                /* Extensions  ::=  SEQUENCE SIZE (1..N) */
                extension_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, tbscert_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &extension_length, NULL, &iterator_lastbyte, &decode_error, NULL);
                if (decode_error != 0) {
                    return decode_error;
                }
                if (iterator_lastbyte != tbsCertificate_index + tbsCertificate_length) {
                    return PTLS_ALERT_BAD_CERTIFICATE;
                }

                /* Extension  ::=  SEQUENCE  {
                 *      extnID      OBJECT IDENTIFIER,
                 *      critical    BOOLEAN DEFAULT FALSE,
                 *      extnValue   OCTET STRING  }
                 */
                for(iterator_lastbyte=extension_index; iterator_lastbyte < lastbyte;) {
                    static const uint8_t oid_basic_constraints[] = {0x55, 0x1d, 0x13},
                                         oid_key_usage[] = {0x55, 0x1d, 0x0f},
                                         oid_extended_key_usage[] = {0x55, 0x1d, 0x25},
                                         oid_any_extended_key_usage[] = {0x55, 0x1d, 0x25, 0x00},
                                         oid_subject_alt_name[] = {0x55, 0x1d, 0x11},
                                         oid_ns_cert_type[] = {0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42, 0x01, 0x01},
                                         oid_certificate_policies[] = {0x55, 0x1d, 0x20},
                                         oid_subject_key_identifier[] = {0x55, 0x1d, 0x0e},
                                         oid_authority_key_identifier[] = {0x55, 0x1d, 0x23},
                                         oid_any_policy[] = {0x55, 0x1d, 0x20, 0x00};
                    int decode_error = 0;
                    size_t it_index, it_lastbyte, ext_index, ext_lastbyte;
                    uint32_t it_length, ext_length;
                    int structure_bit, type_class;
                    uint32_t type_number;
                    int x509_ext = 0, is_critical = 0;

                    extension_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, iterator_lastbyte, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &extension_length, NULL, &iterator_lastbyte, &decode_error, NULL);
                    if (decode_error != 0) {
                        return decode_error;
                    }

                    /* extension-id */
                    it_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, extension_index, ASN1_OID, &it_length, NULL, &it_lastbyte, &decode_error, NULL);
                    if (decode_error != 0) {
                        return decode_error;
                    }
                    if (it_length == sizeof(oid_basic_constraints) && memcmp(cert_raw + it_index, oid_basic_constraints, sizeof(oid_basic_constraints)) == 0) {
                        x509_ext = X509_EXT_BASIC_CONSTRAINTS;
                    }
                    else if (it_length == sizeof(oid_key_usage) && memcmp(cert_raw + it_index, oid_key_usage, sizeof(oid_key_usage)) == 0) {
                        x509_ext = X509_EXT_KEY_USAGE;
                    }
                    else if (it_length == sizeof(oid_extended_key_usage) && memcmp(cert_raw + it_index, oid_extended_key_usage, sizeof(oid_extended_key_usage)) == 0) {
                        x509_ext = X509_EXT_EXTENDED_KEY_USAGE;
                    }
                    else if (it_length == sizeof(oid_any_extended_key_usage) && memcmp(cert_raw + it_index, oid_any_extended_key_usage, sizeof(oid_any_extended_key_usage)) == 0) {
                        x509_ext = X509_EXT_ANY_EXTENDED_KEY_USAGE;
                    }
                    else if (it_length == sizeof(oid_subject_alt_name) && memcmp(cert_raw + it_index, oid_subject_alt_name, sizeof(oid_subject_alt_name)) == 0) {
                        x509_ext = X509_EXT_SUBJECT_ALT_NAME;
                    }
                    else if (it_length == sizeof(oid_ns_cert_type) && memcmp(cert_raw + it_index, oid_ns_cert_type, sizeof(oid_ns_cert_type)) == 0) {
                        x509_ext = X509_EXT_NS_CERT_TYPE;
                    }
                    else if (it_length == sizeof(oid_certificate_policies) && memcmp(cert_raw + it_index, oid_certificate_policies, sizeof(oid_certificate_policies)) == 0) {
                        x509_ext = X509_EXT_CERTIFICATE_POLICIES;
                    }
                    else if (it_length == sizeof(oid_subject_key_identifier) && memcmp(cert_raw + it_index, oid_subject_key_identifier, sizeof(oid_subject_key_identifier)) == 0) {
                        x509_ext = X509_EXT_SUBJECT_KEY_IDENTIFIER;
                    }
                    else if (it_length == sizeof(oid_authority_key_identifier) && memcmp(cert_raw + it_index, oid_authority_key_identifier, sizeof(oid_authority_key_identifier)) == 0) {
                        x509_ext = X509_EXT_AUTHORITY_KEY_IDENTIFIER;
                    }
                    else if (it_length == sizeof(oid_any_policy) && memcmp(cert_raw + it_index, oid_any_policy, sizeof(oid_any_policy)) == 0) {
                        x509_ext = X509_EXT_ANY_POLICY;
                    }

                    /* critical is optional */
                    ptls_asn1_read_type(cert_raw + it_lastbyte, cert_raw_len - it_lastbyte, &structure_bit, &type_class, &type_number, &decode_error, 0, NULL);
                    if (structure_bit == 0 && type_class == 0 && type_number == ASN1_BOOLEAN) {
                        it_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, it_lastbyte, ASN1_BOOLEAN, &it_length, NULL, &it_lastbyte, &decode_error, NULL);
                        if (decode_error != 0) {
                            return decode_error;
                        }
                        if (cert_raw[it_index] != 0) {
                            is_critical = 1;
                        }
                    }

                    /* payload == octet-string */
                    it_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, it_lastbyte, ASN1_OCTET_STRING, &it_length, NULL, &it_lastbyte, &decode_error, NULL);
                    if (decode_error != 0) {
                        return decode_error;
                    }
                    if (it_lastbyte != iterator_lastbyte) {
                        return PTLS_ALERT_BAD_CERTIFICATE;
                    }

                    /* parse extension */
                    if (x509_ext == X509_EXT_BASIC_CONSTRAINTS) {
                        size_t lastbyte, index;
                        uint32_t length;
                        /* BasicConstraints ::= SEQUENCE {
                         *      cA                      BOOLEAN DEFAULT FALSE,
                         *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
                         */
                        index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, it_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &length, NULL, &lastbyte, &decode_error, NULL);
                        if (decode_error != 0) {
                            return decode_error;
                        }
                        if (lastbyte != it_lastbyte) {
                            return PTLS_ALERT_BAD_CERTIFICATE;
                        }

                        if (length != 0) {
                            index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, index, ASN1_BOOLEAN, &length, NULL, &lastbyte, &decode_error, NULL);
                            if (decode_error != 0) {
                                return decode_error;
                            }
                            cert->is_CA = cert_raw[index] != 0;

                            if (lastbyte != it_lastbyte) {
                                size_t i;
                                index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, lastbyte, ASN1_INTEGER, &length, NULL, &lastbyte, &decode_error, NULL);
                                if (decode_error != 0) {
                                    return decode_error;
                                }
                                if (lastbyte != it_lastbyte) {
                                    return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                                }
                                for (i=0; i < length; ++i) {
                                    cert->max_pathlen <<= 8;
                                    cert->max_pathlen |= cert_raw[index + i];
                                }
                            }
                        }
                    }
                    else if (x509_ext == X509_EXT_KEY_USAGE) {
                        size_t lastbyte, index, i, unused_bits;
                        uint32_t length;
                        index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, it_index, ASN1_BIT_STRING, &length, NULL, &lastbyte, &decode_error, NULL);
                        if (decode_error != 0) {
                            return decode_error;
                        }
                        if (lastbyte != it_lastbyte) {
                            return PTLS_ALERT_BAD_CERTIFICATE;
                        }

                        /* Empty bitstring is not an ASN1 error condition */
                        if (length != 0) {
                            unused_bits = cert_raw[index];
                            if (unused_bits > 7) {
                                return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                            }
                            for (i=1; i < length; ++i) {
                                uint8_t bits = cert_raw[index + i];
                                if (i == 1 && (bits & 0x80) != 0)
                                    cert->keyusage_digital_signature = 1;
                                if (i == 1 && (bits & 0x40) != 0)
                                    cert->keyusage_non_repudiation = 1;
                                if (i == 1 && (bits & 0x20) != 0)
                                    cert->keyusage_key_encipherment = 1;
                                if (i == 1 && (bits & 0x10) != 0)
                                    cert->keyusage_data_encipherment = 1;
                                if (i == 1 && (bits & 0x08) != 0)
                                    cert->keyusage_key_agreement = 1;
                                if (i == 1 && (bits & 0x04) != 0)
                                    cert->keyusage_key_cert_sign = 1;
                                if (i == 1 && (bits & 0x02) != 0)
                                    cert->keyusage_crl_sign = 1;
                                if (i == 1 && (bits & 0x01) != 0)
                                    cert->keyusage_encipher_only = 1;
                                if (i == 2 && (bits & 0x80) != 0)
                                    cert->keyusage_decipher_only = 1;
                            }
                        }
                    }
                    else if (x509_ext == X509_EXT_EXTENDED_KEY_USAGE) {
                        /* parse OID */
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_ANY_EXTENDED_KEY_USAGE) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_SUBJECT_ALT_NAME) {
                        int status;
                        ext_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, it_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &ext_length, NULL, &ext_lastbyte, &decode_error, NULL);
                        if (decode_error != 0) {
                            return decode_error;
                        }
                        if (ext_lastbyte != it_lastbyte) {
                            return PTLS_ALERT_BAD_CERTIFICATE;
                        }
                        status = parse_der_subject_alt_name(cert_raw + ext_index, ext_length, &cert->subject_alt_name);
                        if (status != 0) {
                            return status;
                        }
                        cert->v3_subject_alternative_name = 1;
                    }
                    else if (x509_ext == X509_EXT_NS_CERT_TYPE) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_CERTIFICATE_POLICIES) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_SUBJECT_KEY_IDENTIFIER) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_AUTHORITY_KEY_IDENTIFIER) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (x509_ext == X509_EXT_ANY_POLICY) {
                        if (is_critical != 0)  {
                            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                        }
                    }
                    else if (is_critical != 0) {
                        return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
                    }
                }
                if (iterator_lastbyte != tbscert_index + tbscert_length) {
                    return PTLS_ALERT_BAD_CERTIFICATE;
                }
            }
        }

        if (lastbyte != tbsCertificate_index + tbsCertificate_length) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
    }
    else {
        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
    }

    /* SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *       algorithm         AlgorithmIdentifier,
     *       subjectPublicKey  BIT STRING
     * }
     * AlgorithmIdentifier  ::=  SEQUENCE  {
     *        algorithm   OBJECT IDENTIFIER,
     *        parameters  ANY DEFINED BY algorithm OPTIONAL
     * }
     */
    if (signatureAlgorithm_length != 0) {
        static const uint8_t sha1WithRSAEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05},
                             sha224WithRSAEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x10, 0x01, 0x05},
                             sha256WithRSAEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b},
                             sha384WithRSAEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c},
                             sha512WithRSAEncryption[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d},
                             ecdsa_with_SHA1[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01},
                             ecdsa_with_SHA224[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01},
                             ecdsa_with_SHA256[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02},
                             ecdsa_with_SHA384[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03},
                             ecdsa_with_SHA512[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04};
        uint32_t oid_length;
        size_t oid_index = ptls_asn1_get_expected_type_and_length(cert_raw, cert_raw_len, signatureAlgorithm_index, ASN1_OID, &oid_length, NULL, &lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        /*if (lastbyte != signatureAlgorithm_index + signatureAlgorithm_length) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }*/

        /* must match */
        if (oid_length != tbsCertificate_oid_length) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        if (memcmp(cert_raw + oid_index, cert_raw + tbsCertificate_oid_index, oid_length) != 0) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        /* oid-name switch */
        if (oid_length == sizeof(sha1WithRSAEncryption) && memcmp(cert_raw + oid_index, sha1WithRSAEncryption, sizeof(sha1WithRSAEncryption)) == 0) {
            cert->signature_algorithm = PTLS_SIGNATURE_RSA_PKCS1_SHA1;
        }
        else if (oid_length == sizeof(sha224WithRSAEncryption) && memcmp(cert_raw + oid_index, sha224WithRSAEncryption, sizeof(sha224WithRSAEncryption)) == 0) {
            /*cert->signature_algorithm = ;*/
        }
        else if (oid_length == sizeof(sha256WithRSAEncryption) && memcmp(cert_raw + oid_index, sha256WithRSAEncryption, sizeof(sha256WithRSAEncryption)) == 0) {
            cert->signature_algorithm = PTLS_SIGNATURE_RSA_PKCS1_SHA256;
        }
        else if (oid_length == sizeof(sha384WithRSAEncryption) && memcmp(cert_raw + oid_index, sha384WithRSAEncryption, sizeof(sha384WithRSAEncryption)) == 0) {
            /*cert->signature_algorithm = ;*/
        }
        else if (oid_length == sizeof(sha512WithRSAEncryption) && memcmp(cert_raw + oid_index, sha512WithRSAEncryption, sizeof(sha512WithRSAEncryption)) == 0) {
            /*cert->signature_algorithm = ;*/
        }
        else if (oid_length == sizeof(ecdsa_with_SHA1) && memcmp(cert_raw + oid_index, ecdsa_with_SHA1, sizeof(ecdsa_with_SHA1)) == 0) {
            /*cert->signature_algorithm = ;*/
        }
        else if (oid_length == sizeof(ecdsa_with_SHA224) && memcmp(cert_raw + oid_index, ecdsa_with_SHA224, sizeof(ecdsa_with_SHA224)) == 0) {
            /*cert->signature_algorithm = ;*/
        }
        else if (oid_length == sizeof(ecdsa_with_SHA256) && memcmp(cert_raw + oid_index, ecdsa_with_SHA256, sizeof(ecdsa_with_SHA256)) == 0) {
            cert->signature_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
        }
        else if (oid_length == sizeof(ecdsa_with_SHA384) && memcmp(cert_raw + oid_index, ecdsa_with_SHA384, sizeof(ecdsa_with_SHA384)) == 0) {
            cert->signature_algorithm = PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384;
        }
        else if (oid_length == sizeof(ecdsa_with_SHA512) && memcmp(cert_raw + oid_index, ecdsa_with_SHA512, sizeof(ecdsa_with_SHA512)) == 0) {
            cert->signature_algorithm = PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512;
        }
        else {
            return PTLS_ERROR_NOT_AVAILABLE;
        }
    }
    else {
        return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
    }

    if (signatureValue_length != 0) {
        if (parse_der_trim_bitstring(cert_raw, &signatureValue_index, &signatureValue_length) != 0) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }

        cert->signature.base = cert_raw + signatureValue_index;
        cert->signature.len = signatureValue_length;
    }

    return 0;
}


/* Verify signature */

static int verify_signature(const ptls_minicrypto_certificate_t *cert, uint16_t algo, const uint8_t *data, uint32_t datalen, const uint8_t *signature_der, uint32_t signature_der_len)
{
    /* RSA */
    if (algo == PTLS_SIGNATURE_RSA_PKCS1_SHA1 || algo == PTLS_SIGNATURE_RSA_PKCS1_SHA256) {
        int decode_error;
        size_t rsa_index, rsa_lastbyte;
        uint32_t rsa_length, hash_length;
        const uint8_t *publickey_offset = cert->publickey.base, *rsa_N_offset, *rsa_E_offset;
        uint32_t publickey_length = cert->publickey.len, rsa_N_length, rsa_E_length;
        uint8_t hash[32];

        /* RSAPublicKey ::= SEQUENCE {
         *      modulus           INTEGER,  -- N
         *      publicExponent    INTEGER   -- E
         */
        rsa_index = ptls_asn1_get_expected_type_and_length(publickey_offset, publickey_length, 0, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &rsa_length, NULL, &rsa_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (rsa_lastbyte != publickey_length) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        rsa_index = ptls_asn1_get_expected_type_and_length(publickey_offset, publickey_length, rsa_index, ASN1_INTEGER, &rsa_length, NULL, &rsa_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (parse_der_trim_integer(publickey_offset, &rsa_index, &rsa_length) != 0) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
        rsa_N_offset = publickey_offset + rsa_index;
        rsa_N_length = rsa_length;

        rsa_index = ptls_asn1_get_expected_type_and_length(publickey_offset, publickey_length, rsa_lastbyte, ASN1_INTEGER, &rsa_length, NULL, &rsa_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (rsa_lastbyte != publickey_length) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
        if (parse_der_trim_integer(publickey_offset, &rsa_index, &rsa_length) != 0) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
        rsa_E_offset = publickey_offset + rsa_index;
        rsa_E_length = rsa_length;

        /* calc hash */
        if (algo == PTLS_SIGNATURE_RSA_PKCS1_SHA1) {
            return PTLS_ERROR_NOT_AVAILABLE;
        }
        else if (algo == PTLS_SIGNATURE_RSA_PKCS1_SHA256) {
            cf_sha256_context ctx;
            cf_sha256_init(&ctx);
            cf_sha256_update(&ctx, data, datalen);
            cf_sha256_digest_final(&ctx, hash);
            hash_length = 32;
        }

        /* TODO: modular exponentiation */
        (void)rsa_N_offset;
        (void)rsa_N_length;
        (void)rsa_E_offset;
        (void)rsa_E_length;
        (void)hash_length;
        return PTLS_ERROR_NOT_AVAILABLE;
    }

    else if (algo == PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 || algo == PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 || algo == PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512) {
        return PTLS_ERROR_NOT_AVAILABLE;
    }

    /* Elliptic curve */
    else if (algo == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 || algo == PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 || algo == PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512) {
        int decode_error = 0, ret = 0;
        size_t byte_index = 0,
               s_index, r_index;
        uint32_t msg_length = 0,
                 s_length = 0,
                 r_length = 0;
        size_t msg_lastbyte, s_lastbyte, r_lastbyte;

        /* decode DER-signature */
        byte_index = ptls_asn1_get_expected_type_and_length(signature_der, signature_der_len, byte_index, ASN1_CONSTRUCTED|ASN1_SEQUENCE, &msg_length, NULL, &msg_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (msg_lastbyte != signature_der_len) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        s_index = ptls_asn1_get_expected_type_and_length(signature_der, signature_der_len, byte_index, ASN1_INTEGER, &s_length, NULL, &s_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (parse_der_trim_integer(signature_der, &s_index, &s_length) != 0) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }

        r_index = ptls_asn1_get_expected_type_and_length(signature_der, signature_der_len, s_index + s_length, ASN1_INTEGER, &r_length, NULL, &r_lastbyte, &decode_error, NULL);
        if (decode_error != 0) {
            return decode_error;
        }
        if (parse_der_trim_integer(signature_der, &r_index, &r_length) != 0) {
            return PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
        if (r_lastbyte != signature_der_len) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }

        /* calc hash */
        if (algo == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
            uint8_t public_key[32*2];
            unsigned char signature_raw[32*2];
            uint8_t hash[32];

            /* X9.62: prefix 0x04 means uncompressed, followed by bytes x-coordinate + y-coordinate; 0x02+0x03 is compressed; */
            if (cert->publickey.len == 1+sizeof(public_key) && cert->publickey.base[0] == 0x04) {
                memcpy(public_key, cert->publickey.base + 1, sizeof(public_key));
            }
            else if (cert->publickey.len == 1+32 && (cert->publickey.base[0] == 0x02 || cert->publickey.base[0] == 0x03)) {
                uECC_decompress(cert->publickey.base + 1, public_key, uECC_secp256r1());
            }
            else {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            /* coordinate-size (e.g. 256bit) must fit signature-buffer */
            if (s_length > sizeof(signature_raw)/2 || r_length > sizeof(signature_raw)/2) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }
            memset(signature_raw, 0, sizeof(signature_raw));
            memcpy(signature_raw + (sizeof(signature_raw)/2 - s_length), signature_der + s_index, s_length);
            memcpy(signature_raw + sizeof(signature_raw) - r_length, signature_der + r_index, r_length);

            /* hash */
            cf_sha256_context ctx;
            cf_sha256_init(&ctx);
            cf_sha256_update(&ctx, data, datalen);
            cf_sha256_digest_final(&ctx, hash);

            /* verify the signature */
            ret = uECC_verify(public_key, hash, sizeof(hash), signature_raw, uECC_secp256r1());
            if (ret == 1) {
                return 0;
            }
            return PTLS_ALERT_DECRYPT_ERROR;
        }
        else if (algo == PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384) {
            uint8_t public_key[48*2];
            unsigned char signature_raw[48*2];
            uint8_t hash[48];

            /* X9.62: prefix 0x04 means uncompressed, followed by bytes x-coordinate + y-coordinate; 0x02+0x03 is compressed; */
            if (cert->publickey.len == 1+sizeof(public_key) && cert->publickey.base[0] == 0x04) {
                uint64_t i;
                for (i = 0; i < 48; ++i) {
                    public_key[i+1] = cert->publickey.base[i + 1];
                }
                public_key[0] = 2 + (cert->publickey.base[48 * 2] & 0x01);
            }
            else if (cert->publickey.len == 1+48 && (cert->publickey.base[0] == 0x02 || cert->publickey.base[0] == 0x03)) {
                memcpy(public_key, cert->publickey.base + 1, cert->publickey.len-1);
            }
            else {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            /* coordinate-size (e.g. 384bit) must fit signature-buffer */
            if (s_length > sizeof(signature_raw)/2 || r_length > sizeof(signature_raw)/2) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }
            memset(signature_raw, 0, sizeof(signature_raw));
            memcpy(signature_raw + (sizeof(signature_raw)/2 - s_length), signature_der + s_index, s_length);
            memcpy(signature_raw + sizeof(signature_raw) - r_length, signature_der + r_index, r_length);

            /* hash */
            cf_sha512_context ctx;
            cf_sha384_init(&ctx);
            cf_sha384_update(&ctx, data, datalen);
            cf_sha384_digest_final(&ctx, hash);

            /* https://github.com/jestan/easy-ecc/ */
            ret = ecdsa_verify(public_key, hash, signature_raw);
            if (ret == 1) {
                return 0;
            }
            return PTLS_ALERT_DECRYPT_ERROR;
        }
        else if (algo == PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512) {
            uint8_t public_key[64*2];
            unsigned char signature_raw[64*2];
            uint8_t hash[64];

            /* unlike P-256 or P-384 the key length of P-521 may not always be fixed due to minimum-byte representation */
            if ((cert->publickey.len < 1+65+65 || cert->publickey.len > 1+66+66) && cert->publickey.base[0] == 0x04) {
                memcpy(public_key, cert->publickey.base + 1, sizeof(public_key));
            }
            else if (cert->publickey.len >= 1+64 && (cert->publickey.base[0] == 0x02 || cert->publickey.base[0] == 0x03)) {
                /* TODO: decompress key */
            }
            else {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }

            /* coordinate-size (e.g. 521bit) must fit signature-buffer */
            if (s_length > sizeof(signature_raw)/2 || r_length > sizeof(signature_raw)/2) {
                return PTLS_ALERT_BAD_CERTIFICATE;
            }
            memset(signature_raw, 0, sizeof(signature_raw));
            memcpy(signature_raw + (sizeof(signature_raw)/2 - s_length), signature_der + s_index, s_length);
            memcpy(signature_raw + sizeof(signature_raw) - r_length, signature_der + r_index, r_length);

            /* hash */
            cf_sha512_context ctx;
            cf_sha512_init(&ctx);
            cf_sha512_update(&ctx, data, datalen);
            cf_sha512_digest_final(&ctx, hash);

            /* TODO: verify the signature */
            return PTLS_ERROR_NOT_AVAILABLE;
        }
    }

    return PTLS_ERROR_NOT_AVAILABLE;
}

static int match_key_size(const ptls_minicrypto_certificate_t *cert)
{
    /* Phase out old ciphers */
    if (cert->publickey_type == PUBLIC_KEY_RSA) {
        /* publickey contains encoded N + E */
        size_t rsa_bitlen = cert->publickey.len * 8;
        if (rsa_bitlen < 2050) {
            return 0;
        }
    }
    else if (cert->publickey_type == PUBLIC_KEY_EC || cert->publickey_type == PUBLIC_KEY_EC_DH) {
        /* drop weaker curves */
        if (cert->ec_group != EC_GROUP_SECP256R1 &&
            cert->ec_group != EC_GROUP_SECP384R1 &&
            cert->ec_group != EC_GROUP_SECP521R1 &&
            cert->ec_group != EC_GROUP_SECP256K1 &&
            cert->ec_group != EC_GROUP_BP256R1 &&
            cert->ec_group != EC_GROUP_BP384R1 &&
            cert->ec_group != EC_GROUP_BP512R1) {
            return 0;
        }
    }
    else {
        return 0;
    }

    /* SHA-256 and above */
    if (cert->signature_algorithm != PTLS_SIGNATURE_RSA_PKCS1_SHA1 &&
        cert->signature_algorithm != PTLS_SIGNATURE_RSA_PKCS1_SHA256 &&
        cert->signature_algorithm != PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 &&
        cert->signature_algorithm != PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 &&
        cert->signature_algorithm != PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 &&
        cert->signature_algorithm != PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 &&
        cert->signature_algorithm != PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 &&
        cert->signature_algorithm != PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512) {
        return 0;
    }

    return 1;
}

static int match_server_name(const uint8_t *cert_name, size_t cert_name_len, const char *server_name, size_t server_name_len)
{
    size_t i, server_name_idx = 0;

    /* fast: compare caseless */
    if (cert_name_len == server_name_len) {
        int caseless_equal = 1;
        for (i=0; i < cert_name_len; ++i) {
            uint8_t c1 = cert_name[i],
                    c2 = server_name[i];
            if ('A' <= c1 && c1 <= 'Z') {
                c1 += 0x20;
            }
            if ('A' <= c2 && c2 <= 'Z') {
                c2 += 0x20;
            }
            if (c1 == c2) {
                continue;
            }
            caseless_equal = 0;
            break;
        }
        if (caseless_equal != 0) {
            return 1;
        }
    }

    /* no wildcard? */
    if (cert_name_len < 3 || cert_name[0] != '*' || cert_name[1] != '.') {
        return 0;
    }
    /* matching wildcard */
    for (i=0; i < server_name_len; ++i) {
        if (server_name[i] != '.') {
            continue;
        }
        server_name_idx = i + 1;
        break;
    }
    if (server_name_idx == 0) {
        return 0;
    }
    if (server_name_len - server_name_idx != cert_name_len - 2) {
        return 0;
    }
    return match_server_name(cert_name + 2, cert_name_len - 2, server_name + server_name_idx, server_name_len - server_name_idx);
}

static int match_timestamp(const ptls_minicrypto_datetime_t *validity, const ptls_minicrypto_datetime_t *now)
{
    if (validity->year != now->year) {
        return (int)validity->year - (int)now->year;
    }
    if (validity->month != now->month) {
        return (int)validity->month - (int)now->month;
    }
    if (validity->day != now->day) {
        return (int)validity->day - (int)now->day;
    }
    if (validity->hour != now->hour) {
        return (int)validity->hour - (int)now->hour;
    }
    if (validity->minute != now->minute) {
        return (int)validity->minute - (int)now->minute;
    }
    if (validity->second != now->second) {
        return (int)validity->second - (int)now->second;
    }
    return 0;
}

static int match_issuer_subject(const ptls_minicrypto_oidset_t *issuer, const ptls_minicrypto_oidset_t *subject)
{
    size_t i;
    /* Empty sets may be considered equal - disallow */
    if (subject->entries_length == 0) {
        return 0;
    }
    if (subject->entries_length != issuer->entries_length) {
        return 0;
    }
    /* Skip space-folding and unicode-normalisation in RFC 5280 § 7.1 */
    for (i=0; i < subject->entries_length; ++i) {
        ptls_minicrypto_oidset_entry_t *subject_entry = &subject->entries[i],
                                       *issuer_entry = &issuer->entries[i];
        if (subject_entry->oid_length != issuer_entry->oid_length) {
            return 0;
        }
        if (memcmp(subject_entry->oid_offset, issuer_entry->oid_offset, subject_entry->oid_length) != 0) {
            return 0;
        }
        if (subject_entry->val_length != issuer_entry->val_length) {
            return 0;
        }
        if (memcmp(subject_entry->val_offset, issuer_entry->val_offset, subject_entry->val_length) != 0) {
            return 0;
        }
    }
    return 1;
}

static int verify_cert_chain(const ptls_minicrypto_certificate_t *certs, const char *server_name, const ptls_minicrypto_certificate_t *trust_CAs)
{
    ptls_minicrypto_datetime_t now;
    const ptls_minicrypto_certificate_t *cert;
    uint64_t path_count = 0;

    /* Check server-name */
    if (server_name != NULL) {
        /* RFC-6125 § 6.4.4 : client MUST NOT seek a match for a CN-ID if identifiers include a DNS-ID, SRV-ID, URI-ID */
        int name_matches = 0,
            contains_dns_svg_uri = 0;
        size_t i, server_name_len = strlen(server_name);

        if (certs->v3_subject_alternative_name != 0) {
            /* SAN match as of RFC 5280 § 4.2.1.6 */
            for (i=0; i < certs->subject_alt_name.entries_length; ++i) {
                const ptls_minicrypto_altname_entry_t *entry = &certs->subject_alt_name.entries[i];
                if (entry->length == 0) {
                    break;
                }
                if (entry->type == X509_SAN_DNS_NAME) {
                    contains_dns_svg_uri = 1;
                    if (match_server_name(entry->offset, entry->length, server_name, server_name_len) != 0) {
                        name_matches = 1;
                        break;
                    }
                }
                else if (entry->type == X509_SAN_IP_ADDRESS) {
                    if (entry->length == 4) {
                        struct in_addr addr4;
                        int ret = inet_pton(AF_INET, server_name, &addr4);
                        if (ret == 1 && memcmp(entry->offset, &addr4.s_addr, sizeof(addr4.s_addr)) == 0) {
                            name_matches = 1;
                            break;
                        }
                    }
                    else if (entry->length == 16) {
                        struct in6_addr addr6;
                        int ret = inet_pton(AF_INET6, server_name, &addr6);
                        if (ret == 1 && memcmp(entry->offset, &addr6.s6_addr, sizeof(addr6.s6_addr)) == 0) {
                            name_matches = 1;
                            break;
                        }
                    }
                }
                else if (entry->type == X509_SAN_UNIFORM_RESOURCE_IDENTIFIER) {
                    contains_dns_svg_uri = 1;
                    if (entry->length == server_name_len && memcmp(entry->offset, server_name, server_name_len) == 0) {
                        name_matches = 1;
                        break;
                    }
                }
            }
        }
        if (name_matches == 0 && contains_dns_svg_uri == 0) {
            size_t i;
            for (i=0; i < certs->subject.entries_length; ++i) {
                static const uint8_t oid_at_cn[] = {0x55, 0x04, 0x03};
                ptls_minicrypto_oidset_entry_t *entry = &certs->subject.entries[i];
                if (entry->oid_length != sizeof(oid_at_cn) || memcmp(entry->oid_offset, oid_at_cn, sizeof(oid_at_cn)) != 0) {
                    continue;
                }
                if (match_server_name(entry->val_offset, entry->val_length, server_name, server_name_len) != 0) {
                    name_matches = 1;
                    break;
                }

            }
        }
        if (name_matches == 0) {
            return PTLS_ALERT_BAD_CERTIFICATE;
        }
    }

    /* Current time */
    datetime_utc(&now);

    /* Limit intermediate CAs */
    for (cert=certs; cert != NULL && path_count <= 10; ++path_count) {
        int truststore_then_parent;
        const ptls_minicrypto_certificate_t *trusted_parent = NULL;

        /* Check validity */
        if (match_timestamp(&cert->validity_notBefore, &now) > 0) {
            return PTLS_ALERT_CERTIFICATE_EXPIRED;
        }
        if (match_timestamp(&cert->validity_notAfter, &now) < 0) {
            return PTLS_ALERT_CERTIFICATE_EXPIRED;
        }

        /* Size of signing-key */
        if (match_key_size(cert) == 0) {
            return PTLS_ALERT_UNSUPPORTED_CERTIFICATE;
        }

        /* Check if certificate is locally trusted (self-issued) */
        if (match_issuer_subject(&cert->issuer, &cert->subject) != 0) {
            int locally_trusted = 0;
            const ptls_minicrypto_certificate_t *candidate;

            for (candidate=trust_CAs; candidate != NULL; candidate=candidate->next) {
                /* Validity is considered optional */
                if (match_timestamp(&candidate->validity_notBefore, &now) > 0) {
                    continue;
                }
                if (match_timestamp(&candidate->validity_notAfter, &now) < 0) {
                    continue;
                }
                /* Currently we look for an exact match with trusted-cert - signatures are not checked */
                if (cert->raw_der.len == candidate->raw_der.len && memcmp(cert->raw_der.base, candidate->raw_der.base, cert->raw_der.len) == 0) {
                    locally_trusted = 1;
                    break;
                }
            }
            if (locally_trusted != 0) {
                return 0;
            }
        }

        /* Look for a parent in trusted CAs or up the chain */
        for (truststore_then_parent=0; truststore_then_parent < 2; ++truststore_then_parent) {
            const ptls_minicrypto_certificate_t *candidates = truststore_then_parent == 0 ? trust_CAs : cert->next;
            const ptls_minicrypto_certificate_t *candidate;

            for (candidate=candidates; candidate != NULL && trusted_parent == NULL; candidate=candidate->next) {
                int ret;

                /* Validity is considered optional */
                if (match_timestamp(&candidate->validity_notBefore, &now) > 0) {
                    continue;
                }
                if (match_timestamp(&candidate->validity_notAfter, &now) < 0) {
                    continue;
                }

                /* check size of signing key */
                if (match_key_size(candidate) == 0) {
                    continue;
                }

                /* Candiate must be the issuer */
                if (match_issuer_subject(&cert->issuer, &candidate->subject) == 0) {
                    continue;
                }

                /* Skip checking CA bit and key-usage if locally trusted v1+v2 certificate */
                if (truststore_then_parent == 1 || candidate->version == 3) {
                    if (candidate->is_CA == 0) {
                        continue;
                    }
                    if (candidate->keyusage_key_cert_sign == 0) {
                        continue;
                    }
                }

                /* max_pathlen is zero means infininte */
                if (candidate->max_pathlen != 0 && candidate->max_pathlen <= path_count) {
                    continue;
                }

                /* TODO: Certificate Revocation List (CRL) */

                /* Signature */
                ret = verify_signature(candidate, cert->signature_algorithm,
                    cert->tbs_der.base, cert->tbs_der.len, cert->signature.base, cert->signature.len);
                if (ret != 0) {
                    continue;
                }

                /* Verified and in trusted CA - hooray! */
                if (truststore_then_parent == 0) {
                    return 0;
                }
                trusted_parent = candidate;
                break;
            }
        }
        cert = trusted_parent;
    }
    return PTLS_ALERT_UNKNOWN_CA;
}


/* Picotls interface */

typedef struct {
    ptls_verify_certificate_t super;
    ptls_minicrypto_certificate_t *trust_ca;
} ptls_minicrypto_verify_certificate_t;

static int verifier_callback(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature)
{
    int ret;
    ptls_minicrypto_certificate_t *certificate = (ptls_minicrypto_certificate_t*)verify_ctx;

    if (certificate == NULL) {
        return PTLS_ALERT_ILLEGAL_PARAMETER;
    }

    /* Picotls will call verify_sign with data.base == NULL when it
     * only wants to clear the memory. This is not an error condition */
    if (data.base == NULL) {
        return 0;
    }

    ret = verify_signature(certificate, algo, data.base, data.len, signature.base, signature.len);

    /* free certificates (used once) */
    free_certchain(certificate);
    return ret;
}

static int verify_certificate_cb(ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
    int (**verifier)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    size_t i;
    int status;
    ptls_minicrypto_verify_certificate_t *context = (ptls_minicrypto_verify_certificate_t*)_self;
    ptls_minicrypto_certificate_t *certhead = NULL, *certtail = NULL;

    /* No certs given */
    if (num_certs == 0) {
        return PTLS_ALERT_CERTIFICATE_REQUIRED;
    }

    /* Parse certificate */
    for (i=0; i < num_certs; ++i) {
        /* concat cert-data behind certificate_t */
        ptls_minicrypto_certificate_t *cert = malloc(sizeof(ptls_minicrypto_certificate_t) + certs[i].len);
        memset(cert, 0, sizeof(ptls_minicrypto_certificate_t));
        memcpy(cert + 1, certs[i].base, certs[i].len);
        status = parse_der_certificate(cert, (uint8_t*)(cert + 1), certs[i].len);
        if (status != 0) {
            free_certchain(certhead);
            return status;
        }
        if (certhead == NULL) {
            certhead = cert;
        }
        else {
            certtail->next = cert;
        }
        certtail = cert;
    }

    /* Verify certificate-chain */
    status = verify_cert_chain(certhead, server_name, context->trust_ca);
    if (status != 0) {
        free_certchain(certhead);
        return status;
    }

    /* Setup */
    *verifier = verifier_callback;
    *verify_data = (void*)certhead;
    return 0;
}

int ptls_minicrypto_init_verify_certificate(ptls_context_t *ptls_ctx, const ptls_iovec_t truststore[], size_t truststore_length)
{
    static const uint16_t sign_algos[] = {
        PTLS_SIGNATURE_RSA_PKCS1_SHA1,
        PTLS_SIGNATURE_RSA_PKCS1_SHA256,
        PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
        PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
        PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
        PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
        PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
        UINT16_MAX,
    };
    ptls_minicrypto_certificate_t *tail = NULL;

    /* context */
    ptls_minicrypto_verify_certificate_t *ctx_verify = (ptls_minicrypto_verify_certificate_t*)malloc(sizeof(ptls_minicrypto_verify_certificate_t));
    if (ctx_verify == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    memset(ctx_verify, 0, sizeof(ptls_minicrypto_verify_certificate_t));
    ctx_verify->super.cb = verify_certificate_cb;
    ctx_verify->super.algos = sign_algos;
    ptls_ctx->verify_certificate = &ctx_verify->super;

    /* Parse CAs */
    for( size_t i=0; i < truststore_length; ++i) {
        int status;
        /* concat certificate_t + cert-content */
        ptls_minicrypto_certificate_t *cert = malloc(sizeof(ptls_minicrypto_certificate_t) + truststore[i].len);
        memset(cert, 0, sizeof(ptls_minicrypto_certificate_t));
        memcpy(cert + 1, truststore[i].base, truststore[i].len);
        status = parse_der_certificate(cert, (uint8_t*)(cert + 1), truststore[i].len);
        if (status != 0) {
            free(cert);
            continue;
        }
        if (tail == NULL) {
            ctx_verify->trust_ca = cert;
        }
        else {
            tail->next = cert;
        }
        tail = cert;
    }
    return 0;
}

void ptls_minicrypto_dispose_verify_certificate(ptls_context_t *ptls_ctx)
{
    ptls_minicrypto_verify_certificate_t *context = (ptls_minicrypto_verify_certificate_t*)ptls_ctx->verify_certificate;
    free_certchain(context->trust_ca);
    free(context);
}
