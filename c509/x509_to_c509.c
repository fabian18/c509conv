#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>

#include <nanocbor/nanocbor.h>
#include <mbedtls/asn1.h>

#include "c509_private.h"

#define MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)
#define MBEDTLS_ASN1_CONSTRUCTED_SET (MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)

#ifndef _DEFAULT_SOURCE
/* https://stackoverflow.com/questions/16647819/timegm-cross-platform */
static int days_from_epoch(int y, int m, int d)
{
    y -= m <= 2;
    int era = y / 400;
    int yoe = y - era * 400;                                   // [0, 399]
    int doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;  // [0, 365]
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;           // [0, 146096]
    return era * 146097 + doe - 719468;
}

// It  does not modify broken-down time
static time_t timegm(struct tm *tm)
{
    int year = tm->tm_year + 1900;
    int month = tm->tm_mon;          // 0-11
    if (month > 11)
    {
        year += month / 12;
        month %= 12;
    }
    else if (month < 0)
    {
        int years_diff = (11 - month) / 12;
        year -= years_diff;
        month += 12 * years_diff;
    }
    int days_since_epoch = days_from_epoch(year, month + 1, tm->tm_mday);

    return 60 * (60 * (24L * days_since_epoch + tm->tm_hour) + tm->tm_min) + tm->tm_sec;
}
#endif

static int _parse_utc(int64_t *seconds, const unsigned char *utc)
{
    if (!isdigit(utc[0])  || !isdigit(utc[1]) || !isdigit(utc[2])  || !isdigit(utc[3])  ||
        !isdigit(utc[4])  || !isdigit(utc[5]) || !isdigit(utc[6])  || !isdigit(utc[7])  ||
        !isdigit(utc[8])  || !isdigit(utc[9]) || !isdigit(utc[10]) || !isdigit(utc[11]) ||
        'Z' != utc[12]) {
        return -EINVAL;
    }
    struct tm tm = {0};
    tm.tm_year = (10 * (utc[0] - '0')) + (utc[1] - '0');
    if (tm.tm_year < 50) {
        tm.tm_year += 100;
    }
    tm.tm_mon  = (10 * (utc[2]  - '0')) + (utc[3]  - '0') - 1;
    tm.tm_mday = (10 * (utc[4]  - '0')) + (utc[5]  - '0');
    tm.tm_hour = (10 * (utc[6]  - '0')) + (utc[7]  - '0');
    tm.tm_min  = (10 * (utc[8]  - '0')) + (utc[9]  - '0');
    tm.tm_sec  = (10 * (utc[10] - '0')) + (utc[11] - '0');
    *seconds = timegm(&tm);
    return 0;
}

static ssize_t _enc_signature_value(uint8_t **dst, const uint8_t *dst_end,
                                    const uint8_t **src, const uint8_t *src_end,
                                    c509_sig_algorithm_id_t id)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    int ret;
    c509_signature_t sig;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
            return ret;
        }
        if (len <= 1 || *s) {
            return -ENOTSUP;
        }
        len--;
        s++;
        if (c509_sig_is_rsa(id)) {
            sig.rsa.len = len;
            sig.rsa.value = s;
            s += len;
        }
        else if (c509_sig_is_ec(id)) {
            if ((mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
                return ret;
            }
            if ((mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
                return ret;
            }
            sig.ecdsa.r = s;
            sig.ecdsa.r_len = len;
            s += len;
            while (sig.ecdsa.r_len && !*sig.ecdsa.r) {
                sig.ecdsa.r_len--;
                sig.ecdsa.r++; /* skip leading zeos */
            }
            if ((mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
                return ret;
            }
            sig.ecdsa.s = s;
            sig.ecdsa.s_len = len;
            s += len;
            while (sig.ecdsa.s_len && !*sig.ecdsa.s) {
                sig.ecdsa.s_len--;
                sig.ecdsa.s++; /* skip leading zeros */
            }
        }
        else {
            return -ENOTSUP;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if (c509_sig_is_ec(id)) {
        sig.ecdsa.id = id;
        if ((ret = c509_write_signature_ecdsa(&writer, &sig.ecdsa)) < 0) {
            return ret;
        }
    }
    else {
        sig.rsa.id = id;
        if ((ret = c509_write_signature_rsa(&writer, &sig.rsa)) < 0) {
            return ret;
        }
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_signature_algorithm(uint8_t **dst, const uint8_t *dst_end,
                                        const uint8_t **src, const uint8_t *src_end,
                                        c509_sig_algorithm_id_t *id)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    const c509_sig_algorithm_t *algo = NULL;

    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        src_end = s + len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) != 0) {
            return ret;
        }
        const uint8_t *oid_algo = s;
        size_t oid_algo_len = len;
        s += len;
        const uint8_t *oid_params = NULL;
        size_t oid_params_len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) == 0) {
            oid_params = s;
            oid_params_len = len;
            s += len;
        }
        else if (*s == 0x05) { /* encoding of NULL */
            if (*(s + 1) != 0x00) {
                return -EINVAL;
            }
            oid_params = s;
            oid_params_len = 2;
            s += 2;
        }
        while ((algo = c509_sig_algorithm_iterator(algo))) {
            if (algo->len != oid_algo_len || memcmp(oid_algo, c509_sig_algorithm_get_oid(algo), oid_algo_len)) {
                continue;
            }
            if ((oid_params && !algo->params) || (!oid_params && algo->params)) {
                continue;
            }
            if (oid_params && algo->params) {
                if (algo->params->len != oid_params_len ||
                    memcmp(oid_params, c509_algorithm_parameters_get_oid(algo->params), oid_params_len)) {
                    continue;
                }
            }
            break;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_signature_algorithm(&writer, algo->id)) < 0) {
        return ret;
    }
    *id = algo->id;
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension_key_usage(uint8_t **dst, const uint8_t *dst_end,
                                        const uint8_t **src, const uint8_t *src_end,
                                        c509_extension_key_usage_t *ku)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    assert(ku->extension.id == C509_EXTENSION_KEY_USAGE);
    ssize_t ret;
    ku->usage = 0;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
            return ret;
        }
        const uint8_t *k = s;
        size_t k_len = len;
        s += len;
        if (k[0] > 8 || k_len > 3) {
            return -ENOTSUP;
        }
        memcpy(&ku->usage, k + 1, k_len - 1);
        ku->usage = ntohs(ku->usage);
        ku->usage = (!!(ku->usage & 0x8000)) * 1 +
                    (!!(ku->usage & 0x4000)) * 2 +
                    (!!(ku->usage & 0x2000)) * 4 +
                    (!!(ku->usage & 0x1000)) * 8 +
                    (!!(ku->usage & 0x0800)) * 16 +
                    (!!(ku->usage & 0x0400)) * 32 +
                    (!!(ku->usage & 0x0200)) * 64 +
                    (!!(ku->usage & 0x0100)) * 128 +
                    (!!(ku->usage & 0x0080)) * 256;
        //ku->usage = (uint16_t)ku->usage >> __builtin_ctz((uint16_t)ku->usage);
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_extension_key_usage(&writer, ku)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension_basic_constraints(uint8_t **dst, const uint8_t *dst_end,
                                                const uint8_t **src, const uint8_t *src_end,
                                                c509_extension_basic_constraints_t *bc)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    assert(bc->extension.id == C509_EXTENSION_BASIC_CONSTRAIINTS);
    ssize_t ret;
    bc->ca = false;
    bc->pathlen = -1;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        int ca;
        if ((ret = mbedtls_asn1_get_bool((unsigned char **)&s, src_end, &ca)) == 0) {
            bc->ca = ca;
        }
        else if (ret != MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
            return ret;
        }
        if (((ret = mbedtls_asn1_get_int((unsigned char **)&s, src_end, &bc->pathlen)) != 0) &&
            (ret != MBEDTLS_ERR_ASN1_OUT_OF_DATA)) {
            return ret;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_extension_basic_constraints(&writer, bc)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension_authority_key_identifier(uint8_t **dst, const uint8_t *dst_end,
                                                       const uint8_t **src, const uint8_t *src_end,
                                                       c509_extension_authority_key_identifier_t *aki)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    assert(aki->extension.id == C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER);
    ssize_t ret;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)) != 0) {
            return ret;
        }
        aki->identifier = s;
        aki->identifier_len = len;
        s += len;
        if (((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1)) == 0) ||
            ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2)) == 0)) {
            return -ENOTSUP; /* don´t care to support this */
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_extension_authority_key_identifier(&writer, aki)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension_subject_key_identifier(uint8_t **dst, const uint8_t *dst_end,
                                                     const uint8_t **src, const uint8_t *src_end,
                                                     c509_extension_subject_key_identifier_t *ski)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    assert(ski->extension.id == C509_EXTENSION_SUBJECT_KEY_IDENTIFIER);
    ssize_t ret;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }
        ski->identifier = s;
        ski->identifier_len = len;
        s += len;
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_extension_subject_key_identifier(&writer, ski)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension_ip_resource(uint8_t **dst, const uint8_t *dst_end,
                                          const uint8_t **src, const uint8_t *src_end,
                                          c509_extension_ip_resource_t *ip6_block)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    assert(ip6_block->extension.id == C509_EXTENSION_IP_RESOURCE);
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        if ((ret = c509_write_extension_ip_resource_start(&writer, ip6_block)) < 0) {
            return ret;
        }
        while ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) == 0) {

            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
                return ret;
            }
            if (len != 2 || s[0] != 0x00 || s[1] != 0x02) { /* AFI IPv6 */
                return -ENOTSUP;
            }
            s += len;
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_NULL)) == 0) {
                if ((ret = c509_write_extension_ip_resource_null_finish(&writer)) < 0) {
                    return ret;
                }
            }
            else if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) == 0) {
                if ((ret = c509_write_extension_ip_resource_address_or_range_start(&writer)) < 0) {
                    return ret;
                }
                do {
                    if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) == 0) {
                        memset(&ip6_block->range_or_prefix.res.prefix, 0, sizeof(ip6_block->range_or_prefix.res.prefix));
                        ip6_block->range_or_prefix.type = C509_EXTENSION_IP_RESOURCE_PREFIX;
                        memcpy(ip6_block->range_or_prefix.res.prefix.addr, s + 1, len - 1);
                        ip6_block->range_or_prefix.res.prefix.len = ((len - 1) * 8) - s[0];
                        if ((ret = c509_write_extension_ip_resource_prefix(&writer, &ip6_block->range_or_prefix.res.prefix)) < 0) {
                            return ret;
                        }
                        s += len;
                    }
                    else if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) == 0) {
                        ip6_block->range_or_prefix.type = C509_EXTENSION_IP_RESOURCE_RANGE;
                        uint8_t unused;
                        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
                            return ret;
                        }
                        unused = s[0];
                        if (unused > 7) {
                            return -ENOTSUP;
                        }
                        memset(&ip6_block->range_or_prefix.res.range.min, 0, sizeof(ip6_block->range_or_prefix.res.range.min));
                        memcpy(ip6_block->range_or_prefix.res.range.min, s + 1, len - 1);
                        s += len;
                        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
                            return ret;
                        }
                        unused = s[0];
                        if (unused > 7) {
                            return -ENOTSUP;
                        }
                        memset(&ip6_block->range_or_prefix.res.range.max, 0xff, sizeof(ip6_block->range_or_prefix.res.range.max));
                        memcpy(ip6_block->range_or_prefix.res.range.max, s + 1, len - 1);
                        s += len;
                        ip6_block->range_or_prefix.res.range.max[len - 2] |= (~(((uint8_t)(0xff)) << unused));
                        if ((ret = c509_write_extension_ip_resource_range(&writer, &ip6_block->range_or_prefix.res.range)) < 0) {
                            return ret;
                        }
                    }
                    else {
                        break;
                    }
                } while (1);
                if ((ret = c509_write_extension_ip_resource_address_or_range_finish(&writer)) < 0) {
                    return ret;
                }
            }
            else {
                return -ENOTSUP;
            }
        }
        if ((ret = c509_write_extension_ip_resource_finish(&writer)) < 0) {
            return ret;
        }
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_extension(uint8_t **dst, const uint8_t *dst_end,
                              const uint8_t **src, const uint8_t *src_end,
                              c509_extension_base_t *extn_buf)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    size_t len;
    const c509_extension_t *extn = NULL;
    const uint8_t *s = *src;
    {
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            if (ret == MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
                return 0; /* no more extensions */
            }
        }
        src_end = s + len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) != 0) {
            return ret;
        }
        while ((extn = c509_extension_iterator(extn))) {
            if (extn->len != len || memcmp(c509_extension_get_oid(extn), s, len)) {
                continue;
            }
            break;
        }
        if (!extn) {
            return -ENOTSUP;
        }
        s += len;
        int critical = false;
        mbedtls_asn1_get_bool((unsigned char **)&s, src_end, &critical);
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OCTET_STRING)) != 0) {
            return ret;
        }
        extn_buf->critical = critical;
        extn_buf->id = extn->id;
    }
    uint8_t *dst_cpy = *dst, *d = *dst;
    if (extn->id == C509_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
        if ((ret = _enc_extension_subject_key_identifier(&d, dst_end, &s, s + len,
                    (c509_extension_subject_key_identifier_t *)extn_buf)) < 0) {
            return ret;
        }
    }
    else if (extn->id == C509_EXTENSION_KEY_USAGE) {
        if ((ret = _enc_extension_key_usage(&d, dst_end, &s, s + len,
                    (c509_extension_key_usage_t *)extn_buf)) < 0) {
            return ret;
        }
    }
    else if (extn->id == C509_EXTENSION_BASIC_CONSTRAIINTS) {
        if ((ret = _enc_extension_basic_constraints(&d, dst_end, &s, s + len,
                    (c509_extension_basic_constraints_t *)extn_buf)) < 0) {
            return ret;
        }
    }
    else if (extn->id == C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) {
        if ((ret = _enc_extension_authority_key_identifier(&d, dst_end, &s, s + len,
                    (c509_extension_authority_key_identifier_t *)extn_buf)) < 0) {
            return ret;
        }
    }
    else if (extn->id == C509_EXTENSION_IP_RESOURCE) {
        if ((ret = _enc_extension_ip_resource(&d, dst_end, &s, s + len,
                    (c509_extension_ip_resource_t *)extn_buf)) < 0) {
            return ret;
        }
    }
    *src = s;
    *dst = d;
    return d - dst_cpy;
}

static ssize_t _enc_extensions(uint8_t **dst, const uint8_t *dst_end,
                               const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    bool no_extensions = false;
    bool optimized_ku = true;
    const uint8_t *s = *src;
    {
        size_t len = 0;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len,
                                        MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3)) != 0) {
            if (ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
                return ret;
            }
            /* An omitted 'extensions' field is encoded as an empty CBOR array. */
            no_extensions = true;
        }
        src_end = s + len;
        if ((ret == 0) &&
            (ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    union {
        c509_extension_base_t extension;
        c509_extension_subject_key_identifier_t ski;
        c509_extension_authority_key_identifier_t aki;
        c509_extension_basic_constraints_t bc;
        c509_extension_key_usage_t ku;
        c509_extension_ip_resource_t ip;
    } u_ext;
    if ((ret = c509_write_extensions_start(&writer)) < 0) {
        return ret;
    }
    if (!no_extensions) {
        while ((ret = _enc_extension(&writer.dst, writer.dst_end, &s, src_end, &u_ext.extension)) != 0) {
            if (ret < 0) {
                return ret;
            }
            optimized_ku = optimized_ku && (u_ext.extension.id == C509_EXTENSION_KEY_USAGE);
        }
    }
    if ((ret = c509_write_extensions_finish(&writer)) < 0) {
        return ret;
    }
    if (optimized_ku) {
        writer = C509_WRITER_INITIALIZER(*dst, dst_end);
        if ((ret = c509_write_extension_key_usage_optimized(&writer, &u_ext.ku)) < 0) {
            return ret;
        }
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_subject_unique_id(uint8_t **dst, const uint8_t *dst_end,
                                      const uint8_t **src, const uint8_t *src_end)
{
    (void)dst; (void)dst_end;
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    size_t len;
    if (mbedtls_asn1_get_tag((unsigned char **)src, src_end, &len,
                             MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 2) == 0) {
        return -ENOTSUP;
    }
    return 0;
}

static ssize_t _enc_issuer_unique_id(uint8_t **dst, const uint8_t *dst_end,
                                     const uint8_t **src, const uint8_t *src_end)
{
    (void)dst; (void)dst_end;
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    size_t len;
    if (mbedtls_asn1_get_tag((unsigned char **)src, src_end, &len,
                             MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1) == 0) {
        return -ENOTSUP;
    }
    return 0;
}

static ssize_t _enc_subject_public_key_info(uint8_t **dst, const uint8_t *dst_end,
                                            const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    const c509_pk_algorithm_t *algo = NULL;
    c509_pk_info_t pk;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        src_end = s + len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) != 0) {
            return ret;
        }
        const uint8_t *oid_algo = s;
        size_t oid_algo_len = len;
        s += len;
        const uint8_t *oid_params = NULL;
        size_t oid_params_len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) == 0) {
            oid_params = s;
            oid_params_len = len;
            s += len;
        }
        else if (*s == 0x05) { /* encoding of NULL */
            if (*(s + 1) != 0x00) {
                return -EINVAL;
            }
            oid_params = s;
            oid_params_len = 2;
            s += 2;
        }
        while ((algo = c509_pk_algorithm_iterator(algo))) {
            if (algo->len != oid_algo_len || memcmp(oid_algo, c509_pk_algorithm_get_oid(algo), oid_algo_len)) {
                continue;
            }
            if ((oid_params && !algo->params) || (!oid_params && algo->params)) {
                continue;
            }
            if (oid_params && algo->params) {
                if (algo->params->len != oid_params_len ||
                    memcmp(oid_params, c509_algorithm_parameters_get_oid(algo->params), oid_params_len)) {
                    continue;
                }
            }
            break;
        }
        if (!algo) {
            return -ENOTSUP;
        }
        else if (c509_pk_is_rsa(algo->id)) {
            pk.rsa.id = algo->id;
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
                return ret;
            }
            if (len <= 1 || *s++ != 0) {
                return -ENOTSUP;
            }
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
                return ret;
            }
            pk.rsa.mod_len = len;
            pk.rsa.modulus = s;
            s += len;
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
                return ret;
            }
            pk.rsa.exp_len = len;
            pk.rsa.exponent = s;
            s += len;
        }
        else if (c509_pk_is_ec(algo->id)) {
            pk.ec.id = algo->id;
            if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_BIT_STRING)) != 0) {
                return ret;
            }
            if (len <= 1 || *s++ != 0 || (*s != 0x04 && *s != 0x03 && *s != 0x02)) {
                return -EINVAL;
            }
            pk.ec.len = len - 1;
            pk.ec.point = s;
            s += (len - 1);
        }
        else {
            return -ENOTSUP;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if (c509_pk_is_rsa(algo->id)) {
        if ((ret = c509_write_rsa_subject_public_key_info(&writer, &pk.rsa)) < 0) {
            return ret;
        }
    }
    else if (c509_pk_is_ec(algo->id)) {
        if ((ret = c509_write_ec_subject_public_key_info(&writer, &pk.ec)) < 0) {
            return ret;
        }
    }
    else {
        return -ENOTSUP;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_validity(uint8_t **dst, const uint8_t *dst_end,
                             const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_validity_t validity;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        src_end = s + len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_UTC_TIME)) != 0) {
            return ret;
        }
        if (len != strlen("yymmddhhmmssZ")) {
            return -EINVAL;
        }
        if ((ret = _parse_utc(&validity.not_before, s)) != 0) {
            return -ETIME;
        }
        s += len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_UTC_TIME)) != 0) {
            return ret;
        }
        if (len != strlen("yymmddhhmmssZ")) {
            return -EINVAL;
        }
        if ((ret = _parse_utc(&validity.not_after, s)) != 0) {
            return -ETIME;
        }
        s += len;
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_validity(&writer, &validity)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_name(uint8_t **dst, const uint8_t *dst_end,
                         const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_name_attribute_t attribute;
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    bool optimized_cn = true;

    if ((ret = c509_write_name_start(&writer)) < 0) {
        return ret;
    }
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
            return ret;
        }
        src_end = s + len;
        while ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SET)) == 0) {
            if ((ret = c509_write_name_attribute_start(&writer)) < 0) {
                return ret;
            }
            while ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) == 0) {
                if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_OID)) != 0) {
                    return ret;
                }
                const c509_attribute_t *attr = NULL;
                const uint8_t *oid = s;
                s += len;
                while ((attr = c509_attribute_iterator(attr))) {
                    if ((attr->len != len) || memcmp(c509_attribute_get_oid(attr), oid, len)) {
                        continue;
                    }
                    attribute.id = attr->id;
                    attribute.printable_string = (*s == MBEDTLS_ASN1_PRINTABLE_STRING);
                    s++;
                    if ((ret = mbedtls_asn1_get_len((unsigned char **)&s, src_end, &len)) != 0) {
                        return ret;
                    }
                    attribute.value_len = len;
                    attribute.value = len ? s : NULL;
                    s += len;
                    break;
                }
                if (!attr) {
                    return -ENOTSUP;
                }
                optimized_cn = optimized_cn && attr->id == C509_ATTR_COMMON_NAME;
                if ((ret = c509_write_name_attribute(&writer, &attribute)) < 0) {
                    return ret;
                }
            }
            if ((ret = c509_write_name_attribute_finish(&writer)) < 0) {
                return ret;
            }
        }
        if (ret != MBEDTLS_ERR_ASN1_OUT_OF_DATA) {
            return -EINVAL;
        }
    }
    if ((ret = c509_write_name_finish(&writer)) < 0) {
        return ret;
    }
    if (optimized_cn) {
        writer = C509_WRITER_INITIALIZER(*dst, dst_end);
        if ((ret = c509_write_name_optimized(&writer, attribute.value, attribute.value_len)) < 0) {
            return ret;
        }
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_subject(uint8_t **dst, const uint8_t *dst_end,
                            const uint8_t **src, const uint8_t *src_end)
{
    return _enc_name(dst, dst_end, src, src_end);
}

static ssize_t _enc_issuer(uint8_t **dst, const uint8_t *dst_end,
                           const uint8_t **src, const uint8_t *src_end)
{
    return _enc_name(dst, dst_end, src, src_end);
}

static ssize_t _enc_signature(uint8_t **dst, const uint8_t *dst_end,
                              const uint8_t **src, const uint8_t *src_end)
{
    /* The 'signature' field is always the same as the 'signatureAlgorithm' field
       and therefore omitted from the CBOR encoding */
    (void)dst; (void)dst_end;
    ssize_t ret;
    size_t len= 0;
    if ((ret = mbedtls_asn1_get_tag((unsigned char **)src, src_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
        return ret;
    }
    *src = *src + len;
    return 0;
}

static ssize_t _enc_serial_number(uint8_t **dst, const uint8_t *dst_end,
                                  const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    size_t serial_len = 20;
    const uint8_t *serial;
    /* Certificate users MUST be able to handle serialNumber values up to 20 octets.
       Conforming CAs MUST NOT use serialNumber values longer than 20 octets. */
    const uint8_t *s = *src;
    {
       size_t len;
       if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_INTEGER)) != 0) {
           return ret;
       }
       if (len > serial_len) {
           return -ENOTSUP;
       }
       serial = s;
       serial_len = len;
       s += len;
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_certificate_serial_number(&writer, serial, serial_len)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

static ssize_t _enc_version(uint8_t **dst, const uint8_t *dst_end,
                            const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    const uint8_t *s = *src;
    {
        size_t len;
        if ((ret = mbedtls_asn1_get_tag((unsigned char **)&s, src_end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) != 0) {
            /* Currently, the type can be a natively signed C509 certificate following X.509 v3 (c509CertificateType = 0)
               or a CBOR re-encoded X.509 v3 DER certificate (c509CertificateType = 1) */
            return ret;
        }
        src_end = s + len;
        int version;
        if ((ret = mbedtls_asn1_get_int((unsigned char **)&s, src_end, &version)) != 0) {
            return ret;
        }
        if (version != 2) { /* x509v3 */
            return -EINVAL;
        }
    }
    c509_writer_t writer = C509_WRITER_INITIALIZER(*dst, dst_end);
    if ((ret = c509_write_type(&writer, C509_TYPE_DER)) < 0) {
        return ret;
    }
    ret = writer.dst - *dst;
    *src = s;
    *dst = writer.dst;
    return ret;
}

int x509_to_c509(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    size_t len;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = mbedtls_asn1_get_tag((unsigned char **)&in, in_end, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_get_tag((unsigned char **)&in, in + len, &len, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) != 0) {
        return ret;
    }
    if ((ret = c509_write_certificate_start(&writer)) < 0) {
        return ret;
    }
    if ((ret = _enc_version(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_serial_number(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_signature(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_issuer(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_validity(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_subject(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_subject_public_key_info(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_issuer_unique_id(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_subject_unique_id(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    if ((ret = _enc_extensions(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    c509_sig_algorithm_id_t sig_id = -1;
    if ((ret = _enc_signature_algorithm(&writer.dst, writer.dst_end, &in, in_end, &sig_id)) < 0) {
        return ret;
    }
    if ((ret = _enc_signature_value(&writer.dst, writer.dst_end, &in, in_end, sig_id)) < 0) {
        return ret;
    }
    if ((ret = c509_write_certificate_finish(&writer)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_version(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_version(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_serial_number(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_serial_number(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_signature(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_signature(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_issuer(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_issuer(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_validity(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_validity(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_subject(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_subject(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_subject_public_key_info(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_subject_public_key_info(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_issuer_unique_id(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_issuer_unique_id(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_subject_unique_id(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_subject_unique_id(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_extensions(void *c509, size_t c_size, const void *x509, size_t x_size)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_extensions(&writer.dst, writer.dst_end, &in, in_end)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_signature_algorithm(void *c509, size_t c_size, const void *x509, size_t x_size, c509_sig_algorithm_id_t *sig_id)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_signature_algorithm(&writer.dst, writer.dst_end, &in, in_end, sig_id)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}

int x509_to_c509_enc_signature_value(void *c509, size_t c_size, const void *x509, size_t x_size, c509_sig_algorithm_id_t sig_id)
{
    uint8_t *out = c509;
    uint8_t *out_end = out + c_size;
    const uint8_t *in = x509;
    const uint8_t *in_end = in + x_size;
    ssize_t ret;
    c509_writer_t writer = C509_WRITER_INITIALIZER(out, out_end);
    if ((ret = _enc_signature_value(&writer.dst, writer.dst_end, &in, in_end, sig_id)) < 0) {
        return ret;
    }
    return writer.dst - (uint8_t *)c509;
}
