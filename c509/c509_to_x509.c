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
#include <mbedtls/asn1write.h>
#include <ecc_point_compression.h>

#include "c509_private.h"

#define MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE (MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED)
#define MBEDTLS_ASN1_CONSTRUCTED_SET (MBEDTLS_ASN1_SET | MBEDTLS_ASN1_CONSTRUCTED)

static int _parse_utc(char *utc, int64_t seconds)
{
    time_t tt = seconds;
    struct tm *tm = gmtime(&tt);
    if (tm->tm_year > 100) {
        tm->tm_year -= 100;
    }
    tm->tm_mon += 1;
    utc[0]  = '0' + tm->tm_year / 10; utc[1]  = '0' + tm->tm_year % 10;
    utc[2]  = '0' + tm->tm_mon  / 10; utc[3]  = '0' + tm->tm_mon  % 10;
    utc[4]  = '0' + tm->tm_mday / 10; utc[5]  = '0' + tm->tm_mday % 10;
    utc[6]  = '0' + tm->tm_hour / 10; utc[7]  = '0' + tm->tm_hour % 10;
    utc[8]  = '0' + tm->tm_min  / 10; utc[9]  = '0' + tm->tm_min  % 10;
    utc[10] = '0' + tm->tm_sec  / 10; utc[11] = '0' + tm->tm_sec  % 10;
    utc[12] = 'Z';                    utc[13] = '\0';
    return strlen(utc);
}

static ssize_t _enc_signature_value(uint8_t **dst, const uint8_t *dst_end,
                                    const uint8_t **src, const uint8_t *src_end,
                                    c509_sig_algorithm_id_t id)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    uint8_t *d = (uint8_t *)dst_end;
    if (c509_sig_is_rsa(id)) {
        c509_signature_rsa_t signature;
        signature.id = id;
        if ((ret = c509_read_signature_rsa(&reader, &signature)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_bitstring(&d, *dst, signature.value, signature.len * 8)) < 0) {
            return ret;
        }
    }
    else if (c509_sig_is_ec(id)) {
        c509_signature_ecdsa_t signature;
        signature.id = id;
        if ((ret = c509_read_signature_ecdsa(&reader, &signature)) < 0) {
            return ret;
        }
        size_t len;
        if ((size_t)(d - *dst) < 1 + signature.s_len) {
            return -ENOBUFS;
        }

        d -= signature.s_len;
        memcpy(d, signature.s, signature.s_len);
        len = signature.s_len;
        if (signature.s[0] & 0x80u) {
            *--d = 0x00;
            len++;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, len)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_INTEGER)) < 0) {
            return ret;
        }
        if ((size_t)(d - *dst) < 1 + signature.r_len) {
            return -ENOBUFS;
        }
        d -= signature.r_len;
        memcpy(d, signature.r, signature.r_len);
        len = signature.r_len;
        if (signature.r[0] & 0x80u) {
            *--d = 0x00;
            len++;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, len)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_INTEGER)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
        if (d - *dst < 1) {
            return -ENOBUFS;
        }
        *--d = 0x00;
        if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_BIT_STRING)) < 0) {
            return ret;
        }
    }
    else {
        return -ENOTSUP;
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static ssize_t _enc_signature_algorithm(uint8_t **dst, const uint8_t *dst_end,
                                        const uint8_t **src, const uint8_t *src_end,
                                        c509_sig_algorithm_id_t *id)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    c509_sig_algorithm_id_t sig_id;
    if ((ret = c509_read_signature_algorithm(&reader, &sig_id)) < 0) {
        return ret;
    }
    const c509_sig_algorithm_t *alg = c509_sig_algorithm_get_by_id(sig_id);
    if (!alg) {
        return ret;
    }
    uint8_t *d = (uint8_t *)dst_end;
    if (alg->params) {
        if (c509_algorithm_parameters_is_null(alg->params)) {
            if ((ret = mbedtls_asn1_write_null(&d, *dst)) < 0) {
                return ret;
            }
        }
        else if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_algorithm_parameters_get_oid(alg->params), alg->params->len)) < 0) {
            return ret;
        }
    }
    if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_sig_algorithm_get_oid(alg), alg->len)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    *id = sig_id;
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static ssize_t _enc_extension_ip_resource(uint8_t **dst, const uint8_t *dst_end,
                                          const c509_extension_ip_resource_t *ip)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    uint8_t *d = (uint8_t *)dst_end;
    if (ip->range_or_prefix.type == C509_EXTENSION_IP_RESOURCE_NULL) {
        if ((ret = mbedtls_asn1_write_null(&d, *dst)) < 0) {
            return ret;
        }
    }
    else {
        const c509_extension_ipv6_range_or_prefix_list_t *end = ip->range_or_prefix.next;
        const c509_extension_ipv6_range_or_prefix_list_t *first = ip->range_or_prefix.next;
        size_t addr_or_range_written = 0;
        do {
            if (first->type == C509_EXTENSION_IP_RESOURCE_PREFIX) {
                if ((ret = mbedtls_asn1_write_bitstring(&d, *dst,
                                                        first->res.prefix.addr,
                                                        first->res.prefix.len)) < 0) {
                    return ret;
                }
                addr_or_range_written += ret;
            }
            else if (first->type == C509_EXTENSION_IP_RESOURCE_RANGE) {
                size_t range_written = addr_or_range_written;
                uint8_t nbits = sizeof(first->res.range.max) * 8;
                for (int i = sizeof(first->res.range.max) - 1; i >= 0; i--) {
                    if (first->res.range.max[i] == 0xff) {
                        nbits -= 8;
                        continue;
                    }
                    nbits -= __builtin_ctz(~first->res.range.max[i]);
                    break;
                }
                if ((ret = mbedtls_asn1_write_bitstring(&d, *dst, first->res.range.max, nbits)) < 0) {
                    return ret;
                }
                addr_or_range_written += ret;
                nbits = sizeof(first->res.range.min) * 8;
                for (int i = sizeof(first->res.range.min) - 1; i >= 0; i--) {
                    if (first->res.range.min[i] == 0x00) {
                        nbits -= 8;
                        continue;
                    }
                    nbits -= __builtin_ctz(first->res.range.min[i]);
                    break;
                }
                if ((ret = mbedtls_asn1_write_bitstring(&d, *dst, first->res.range.min, nbits)) < 0) {
                    return ret;
                }
                addr_or_range_written += ret;
                if ((ret = mbedtls_asn1_write_len(&d, *dst, addr_or_range_written - range_written)) < 0) {
                    return ret;
                }
                addr_or_range_written += ret;
                if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
                    return ret;
                }
                addr_or_range_written += ret;
            }
            else {
                return -ENOTSUP;
            }
            first = first->next;
        } while (first != end);
        if ((ret = mbedtls_asn1_write_len(&d, *dst, addr_or_range_written)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
    }
    const uint8_t afi[] = {0x00, 0x02};
    if ((ret = mbedtls_asn1_write_octet_string(&d, *dst, afi, sizeof(afi))) < 2) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    /* TODO: handle IPv4 */
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    return dst_end - d;
}

static ssize_t _enc_extension_key_usage(uint8_t **dst, const uint8_t *dst_end,
                                        const c509_extension_key_usage_t *ku)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    if (ku->usage > ((1u << 10) - 1)) {
        return -ENOTSUP; /* 9 bits */
    }
    uint8_t *d = (uint8_t *)dst_end;
    uint16_t usage = ku->usage;
    usage = ((!!(usage & 1u)) << 8) +
            ((!!(usage & 2u)) << 7) +
            ((!!(usage & 4u)) << 6) +
            ((!!(usage & 8u)) << 5) +
            ((!!(usage & 16u)) << 4) +
            ((!!(usage & 32u)) << 3) +
            ((!!(usage & 64u)) << 2) +
            ((!!(usage & 128u)) << 1) +
            ((!!(usage & 256u)) << 0);
    unsigned bits = 9 - __builtin_ctz((1u << 9) | usage);
    usage <<= (sizeof(usage) * 8 - 9);
    usage = htons(usage);
    if ((ret = mbedtls_asn1_write_bitstring(&d, *dst, (const unsigned char *)&usage, bits)) < 0) {
        return ret;
    }
    return dst_end - d;
}

static ssize_t _enc_extension_basic_constraints(uint8_t **dst, const uint8_t *dst_end,
                                                const c509_extension_basic_constraints_t *bc)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    uint8_t *d = (uint8_t *)dst_end;
    if (bc->pathlen >= 0) {
        if ((ret = mbedtls_asn1_write_int(&d, *dst, bc->pathlen)) < 0) {
            return ret;
        }
    }
    if (bc->ca) {
        if ((ret = mbedtls_asn1_write_bool(&d, *dst, true)) < 0) {
            return ret;
        }
    }
    if ((ret = mbedtls_asn1_write_len(&d,*dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    return dst_end - d;
}

static ssize_t _enc_extension_authority_key_identifier(uint8_t **dst, const uint8_t *dst_end,
                                                       const c509_extension_authority_key_identifier_t *aki)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    uint8_t *d = (uint8_t *)dst_end;
    if (aki->identifier) {
        if ((size_t)(d - *dst) < aki->identifier_len) {
            return -ENOBUFS;
        }
        d -= aki->identifier_len;
        memcpy(d, aki->identifier, aki->identifier_len);
        if ((ret = mbedtls_asn1_write_len(&d,*dst, aki->identifier_len)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d,*dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
    }
    return dst_end - d;
}

static ssize_t _enc_extension_subject_key_identifier(uint8_t **dst, const uint8_t *dst_end,
                                                     const c509_extension_subject_key_identifier_t *ski)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    uint8_t *d = (uint8_t *)dst_end;
    if ((ret = mbedtls_asn1_write_octet_string(&d, *dst, ski->identifier, ski->identifier_len)) < 0) {
        return ret;
    }
    return dst_end - d;
}

static ssize_t _enc_extension(uint8_t **dst, const uint8_t *dst_end,
                              const c509_extension_base_t *base, size_t len)
{
    assert(dst_end >= *dst);
    ssize_t ret;
    const c509_extension_t *extn = c509_extension_get_by_id(base->id);
    if (!extn) {
        return -ENOTSUP;
    }
    uint8_t *d = (uint8_t *)dst_end;
    if ((ret = mbedtls_asn1_write_len(&d, *dst, len)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_OCTET_STRING)) < 0) {
        return ret;
    }
    if (base->critical) {
        if ((ret = mbedtls_asn1_write_bool(&d, *dst, true)) < 0) {
            return ret;
        }
    }
    if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_extension_get_oid(extn), extn->len)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_len(&d, *dst, len + (dst_end - d))) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    return dst_end - d;
}

static ssize_t _enc_extensions(uint8_t **dst, const uint8_t *dst_end,
                              const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    uint8_t *d = (uint8_t *)dst_end;
    union _C509_BUF_ALIGNED {
        uint8_t buf[512];
        c509_extension_list_t list;
    } extensions;
    size_t extensioins_buf_size = sizeof(extensions.buf);
    if ((ret = c509_read_extensions(&reader, extensions.buf, &extensioins_buf_size)) < 0) {
        return ret;
    }
    c509_extension_list_t *ext = extensions.list.next;
    do {
        if (ext->extension.id == C509_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
            if ((ret = _enc_extension_subject_key_identifier(dst, d,
                        (const c509_extension_subject_key_identifier_t *)&ext->extension)) < 0) {
                return ret;
            }
        }
        else if (ext->extension.id == C509_EXTENSION_KEY_USAGE) {
            if ((ret = _enc_extension_key_usage(dst, d,
                        (const c509_extension_key_usage_t *)&ext->extension)) < 0) {
                return ret;
            }
        }
        else if (ext->extension.id == C509_EXTENSION_BASIC_CONSTRAIINTS) {
            if ((ret = _enc_extension_basic_constraints(dst, d,
                        (const c509_extension_basic_constraints_t *)&ext->extension)) < 0) {
                return ret;
            }
        }
        else if (ext->extension.id == C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) {
            if ((ret = _enc_extension_authority_key_identifier(dst, d,
                        (const c509_extension_authority_key_identifier_t *)&ext->extension)) < 0) {
                return ret;
            }
        }
        else if (ext->extension.id == C509_EXTENSION_IP_RESOURCE) {
            if ((ret = _enc_extension_ip_resource(dst, d,
                        (const c509_extension_ip_resource_t *)&ext->extension)) < 0) {
                return ret;
            }
        }
        else {
            return -ENOTSUP;
        }
        d -= ret;
        if ((ret = _enc_extension(dst, d, &ext->extension, ret)) < 0) {
            return ret;
        }
        d -= ret;
        ext = ext->next;
    } while (ext != extensions.list.next);
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 3)) < 0) {
        return ret;
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static inline mbedtls_ecp_group_id _mbedtls_ecp_get_group_id(c509_pk_algorithm_id_t id)
{
    if (id == C509_PK_ALGORITHM_EC_SECP256R1) {
        return MBEDTLS_ECP_DP_SECP256R1;
    }
    if (id == C509_PK_ALGORITHM_EC_SECP384R1) {
        return MBEDTLS_ECP_DP_SECP384R1;
    }
    if (id == C509_PK_ALGORITHM_EC_SECP521R1) {
        return MBEDTLS_ECP_DP_SECP521R1;
    }
    return -1;
}

static ssize_t _enc_subject_public_key_info(uint8_t **dst, const uint8_t *dst_end,
                                            const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    c509_pk_info_t pki;
    if ((ret = c509_read_subject_public_key_info(&reader, &pki)) < 0) {
        return ret;
    }
    uint8_t *d = (uint8_t *)dst_end;
    {
        const c509_pk_algorithm_t *alg = c509_pk_algorithm_get_by_id(pki.id);
        if (!alg) {
            return -ENOTSUP;
        }
        if (c509_pk_is_rsa(alg->id)) {
            if ((size_t)(d - *dst) < pki.rsa.exp_len) {
                return -ENOBUFS;
            }
            d -= pki.rsa.exp_len;
            memcpy(d, pki.rsa.exponent, pki.rsa.exp_len);
            if ((ret = mbedtls_asn1_write_len(&d, *dst, pki.rsa.exp_len)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_INTEGER)) < 0) {
                return ret;
            }
            if ((size_t)(d - *dst) < pki.rsa.mod_len) {
                return -ENOBUFS;
            }
            d -= pki.rsa.mod_len;
            memcpy(d, pki.rsa.modulus, pki.rsa.mod_len);
            if ((ret = mbedtls_asn1_write_len(&d, *dst, pki.rsa.mod_len)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_INTEGER)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
                return ret;
            }
            if (d - *dst < 1) {
                return -ENOBUFS;
            }
            *--d = 0x00;
            if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_BIT_STRING)) < 0) {
                return ret;
            }
        }
        else if (c509_pk_is_ec(alg->id)) {
            if ((pki.ec.point[0] != 0xfd) &&
                (pki.ec.point[0] != 0xfe)) {
                return -ENOTSUP;
            }
            uint8_t ec_pk_buf[256];
            ec_pk_buf[0] = pki.ec.point[0] == 0xfd ? 0x03 : 0x02;
            memcpy(ec_pk_buf + 1, pki.ec.point + 1, pki.ec.len - 1);
            size_t ec_pk_len = pki.ec.len;
            mbedtls_ecp_group grp;
            mbedtls_ecp_group_init(&grp);
            if ((ret = mbedtls_ecp_group_load(&grp, _mbedtls_ecp_get_group_id(alg->id))) != 0) {
                return -ENOTSUP;
            }
            if ((ret = mbedtls_ecp_decompress(&grp, ec_pk_buf, ec_pk_len, ec_pk_buf, &ec_pk_len, sizeof(ec_pk_buf)))) {
                return -ENOTSUP;
            }
            if ((size_t)(d - *dst) < ec_pk_len + 1) {
                return -ENOBUFS;
            }
            d -= ec_pk_len;
            memcpy(d, ec_pk_buf, ec_pk_len);
            *--d = 0x00;
            if ((ret = mbedtls_asn1_write_len(&d, *dst, ec_pk_len + 1)) < 0) {
                return ret;
            }
            if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_BIT_STRING)) < 0) {
                return ret;
            }
        }
        else {
            return -ENOTSUP;
        }
        size_t size = 0;
        if (alg->params) {
            if (c509_algorithm_parameters_is_null(alg->params)) {
                if ((ret = mbedtls_asn1_write_null(&d, *dst)) < 0) {
                    return ret;
                }
            }
            else if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_algorithm_parameters_get_oid(alg->params), alg->params->len)) < 0) {
                return ret;
            }
            size += ret;
        }
        if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_pk_algorithm_get_oid(alg), alg->len)) < 0) {
            return ret;
        }
        size += ret;
        if ((ret = mbedtls_asn1_write_len(&d, *dst, size)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static ssize_t _enc_validity(uint8_t **dst, const uint8_t *dst_end,
                             const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    c509_validity_t validity;
    if ((ret = c509_read_validity(&reader, &validity)) < 0) {
        return ret;
    }
    uint8_t *d = (uint8_t *)dst_end;
    {
        char utc[16];
        size_t size;
        _parse_utc(utc, validity.not_after);
        if ((ret = mbedtls_asn1_write_raw_buffer(&d, *dst, (const unsigned char *)utc, size = strlen(utc))) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, size)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_UTC_TIME)) < 0) {
            return ret;
        }
        _parse_utc(utc, validity.not_before);
        if ((ret = mbedtls_asn1_write_raw_buffer(&d, *dst, (const unsigned char *)utc, size = strlen(utc))) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, size)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_UTC_TIME)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static ssize_t _enc_name(uint8_t **dst, const uint8_t *dst_end,
                         const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;
    uint8_t *d = (uint8_t *)dst_end;
    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    c509_name_attribute_t name[8];
    unsigned max = 8;
    if ((ret = c509_read_name(&reader, name, &max)) < 0) {
        return ret;
    }
    for (int i = max - 1; i >= 0; i--) {
        size_t len = 0;
        const c509_attribute_t *attr = c509_attribute_get_by_id(name[i].id);
        if ((ret = (name[i].printable_string
            ? mbedtls_asn1_write_printable_string(&d, *dst, (const char *)name[i].value, name[i].value_len)
            : mbedtls_asn1_write_utf8_string(&d, *dst, (const char *)name[i].value, name[i].value_len))) < 0) {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_oid(&d, *dst, c509_attribute_get_oid(attr), attr->len)) < 0) {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_len(&d, *dst, len)) < 0) {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
            return ret;
        }
        len += ret;
        if ((ret = mbedtls_asn1_write_len(&d, *dst, len)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SET)) < 0) {
            return ret;
        }
    }
    if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
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

static ssize_t _enc_serial(uint8_t **dst, const uint8_t *dst_end,
                           const uint8_t **src, const uint8_t *src_end)
{
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;

    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    const uint8_t *serial;
    size_t serial_len;
    if ((ret = c509_read_serial(&reader, &serial, &serial_len)) < 0) {
        return ret;
    }
    uint8_t *d = (uint8_t *)dst_end;
    {
        if ((size_t)(d - *dst) < serial_len + 1) {
            return -ENOBUFS;
        }
        d = d - serial_len;
        memcpy(d, serial, serial_len);
        if (serial[0] & 0x80u) {
            *--d = 0x00;
            serial_len++;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, serial_len)) <= 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_INTEGER)) <= 0) {
            return ret;
        }
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

static ssize_t _enc_version(uint8_t **dst, const uint8_t *dst_end,
                            const uint8_t **src, const uint8_t *src_end) {
    assert(dst_end >= *dst);
    assert(src_end >= *src);
    ssize_t ret;

    c509_reader_t reader = C509_READER_INITIALIZER(*src, src_end);
    int version;
    if ((ret = c509_read_version(&reader, &version)) < 0) {
        return ret;
    }
    if (version != C509_TYPE_DER) {
        return -ENOTSUP;
    }
    uint8_t *d = (uint8_t *)dst_end;
    {
        if ((ret = mbedtls_asn1_write_int(&d, *dst, 2)) <= 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_len(&d, *dst, dst_end - d)) < 0) {
            return ret;
        }
        if ((ret = mbedtls_asn1_write_tag(&d, *dst, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)) < 0) {
            return ret;
        }
    }
    ret = dst_end - d;
    memmove(*dst, d, ret);
    *src = reader.src;
    *dst = *dst + ret;
    return ret;
}

struct memregion_t {
    uint8_t *start;
    uint8_t *end;
};

static struct memregion_t _reserve(uint8_t **dst, size_t size)
{
    return (struct memregion_t){.start = *dst, .end = *dst += size};
}

int c509_to_x509(void *x509, size_t x_size, const void *c509, size_t c_size)
{
    uint8_t *out = x509;
    uint8_t *out_end = out + x_size;
    const uint8_t *in = c509;
    const uint8_t *in_end = in + c_size;
    ssize_t ret;
    c509_reader_t reader = C509_READER_INITIALIZER(in, in_end);
    c509_array_iterator_t cert_iter;
    if ((ret = c509_read_certificate_start(&reader, &cert_iter)) < 0) {
        return ret;
    }

    struct memregion_t certificate_seq = _reserve(&out, 4);
    size_t certificate_size = 0;

    struct memregion_t tbs_certificate_seq = _reserve(&out, 4);
    size_t tbs_certificate_size = 0;

    if ((ret = _enc_version(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    if ((ret = _enc_serial(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;

    struct memregion_t signature = _reserve(&out, 24);
    size_t signature_size = 0;

    if ((ret = _enc_issuer(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    if ((ret = _enc_validity(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    if ((ret = _enc_subject(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    if ((ret = _enc_subject_public_key_info(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    if ((ret = _enc_extensions(&out, out_end, &reader.src, reader.src_end)) < 0) {
        return ret;
    }
    tbs_certificate_size += ret;
    certificate_size += tbs_certificate_size;

    c509_sig_algorithm_id_t sig_id = -1;
    if ((ret = _enc_signature_algorithm(&out, out_end, &reader.src, reader.src_end, &sig_id)) < 0) {
        return ret;
    }
    certificate_size += ret;
    signature_size = ret;
    if (signature_size > (size_t)(signature.end - signature.start)) {
        return -ENOBUFS;
    }
    memcpy(signature.start, out - signature_size, signature_size);
    tbs_certificate_size += signature_size;
    certificate_size += signature_size;

    if ((ret = _enc_signature_value(&out, out_end, &reader.src, reader.src_end, sig_id)) < 0) {
        return ret;
    }
    certificate_size += ret;
    if ((ret = c509_read_certificate_finish(&reader, &cert_iter)) < 0) {
        return ret;
    }

    memmove(signature.start + signature_size, signature.end, out - signature.end);
    out -= ((signature.end - signature.start) - signature_size);

    uint8_t *ptr;
    size_t len;

    ptr = tbs_certificate_seq.end;
    if ((ret = mbedtls_asn1_write_len(&ptr, tbs_certificate_seq.start, tbs_certificate_size)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&ptr, tbs_certificate_seq.start, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    len = tbs_certificate_seq.end - ptr;
    memmove(tbs_certificate_seq.start, ptr, len);
    memmove(tbs_certificate_seq.start + len, tbs_certificate_seq.end, certificate_size);
    out -= ((tbs_certificate_seq.end - tbs_certificate_seq.start) - len);
    certificate_size += len;

    ptr = certificate_seq.end;
    if ((ret = mbedtls_asn1_write_len(&ptr, certificate_seq.start, certificate_size)) < 0) {
        return ret;
    }
    if ((ret = mbedtls_asn1_write_tag(&ptr, certificate_seq.start, MBEDTLS_ASN1_CONSTRUCTED_SEQUENCE)) < 0) {
        return ret;
    }
    len = certificate_seq.end - ptr;
    memmove(certificate_seq.start, ptr, len);
    memmove(certificate_seq.start + len, certificate_seq.end, certificate_size);
    out -= ((certificate_seq.end - certificate_seq.start) - len);

    return out - (uint8_t *)x509;
}
