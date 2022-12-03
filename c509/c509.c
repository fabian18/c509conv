#include <stdalign.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include <nanocbor/nanocbor.h>

#include "c509_private.h"

static inline size_t _aligned_size(size_t size, uint8_t alignment) {
    return (size + alignment - 1) & ~(alignment - 1);
}

#define ALGORITHM_PARAMETERS_ABSENT     NULL
#define VALIDITY_NO_EXPIRATION          99991231235959

static const uint8_t _65537[] = {0x01, 0x00, 0x01};

#define C509_REGISTRY_ITERATOR_FUNCTION(name, type, registry)                                       \
const type *name(const type *last)                                                                  \
{                                                                                                   \
    if (!last) {                                                                                    \
        return (const type *)&registry;                                                             \
    }                                                                                               \
    const type *end = (const type *)(&((&(registry))[1]));                                          \
    const type *next = (const type *)(((const unsigned char *)last)                                 \
                                     + _aligned_size(sizeof(*last) + last->len, alignof(type)));    \
    return next < end ? next : NULL;                                                                \
}


#define C509_REGISTRY_GET_BY_ID_FUNCTION(name, type, id_type, iterator)                             \
const type *name(id_type id)                                                                        \
{                                                                                                   \
    const type *it = NULL;                                                                          \
    while ((it = iterator(it))) {                                                                   \
        if (it->id == id) {                                                                         \
            return it;                                                                              \
        }                                                                                           \
    }                                                                                               \
    return NULL;                                                                                    \
}

#define C509_REGISTRY_GET_OID_FUNCTION(name, type)                                                  \
const void *name(const type *item)                                                                  \
{                                                                                                   \
    return &item[1];                                                                                \
}


static const struct {
    struct { c509_attribute_t attr; unsigned char _oid[9];  } _0;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _1;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _2;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _3;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _4;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _5;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _6;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _7;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _8;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _9;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _10;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _11;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _12;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _13;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _14;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _15;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _16;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _17;
    struct { c509_attribute_t attr; unsigned char _oid[3];  } _18;
    struct { c509_attribute_t attr; unsigned char _oid[11]; } _19;
    struct { c509_attribute_t attr; unsigned char _oid[11]; } _20;
    struct { c509_attribute_t attr; unsigned char _oid[11]; } _21;
    struct { c509_attribute_t attr; unsigned char _oid[11]; } _22;
} c509_supported_attributes = {
    {{C509_ATTR_EMAIL,
        9},
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01}},
    {{C509_ATTR_COMMON_NAME,
        3},
    {0x55, 0x04, 0x03}},
    {{C509_ATTR_SURNAME,
        3},
    {0x55, 0x04, 0x04}},
    {{C509_ATTR_SERIAL_NUMBER,
        3},
    {0x55, 0x04, 0x05}},
    {{C509_ATTR_COUNTRY,
        3},
    {0x55, 0x04, 0x06}},
    {{C509_ATTR_LOCALITY,
        3},
    {0x55, 0x04, 0x07}},
    {{C509_ATTR_STATE_OR_PROVINCE,
        3},
    {0x55, 0x04, 0x08}},
    {{C509_ATTR_STREET_ADDRESS,
        3},
    {0x55, 0x04, 0x09}},
    {{C509_ATTR_ORGANIZATION,
        3},
    {0x55, 0x04, 0x0A}},
    {{C509_ATTR_ORGANIZATION_UNIT,
        3},
    {0x55, 0x04, 0x0B}},
    {{C509_ATTR_TITLE,
        3},
    {0x55, 0x04, 0x0C}},
    {{C509_ATTR_BUSINESS_CATEGORY,
        3},
    {0x55, 0x04, 0x0F}},
    {{C509_ATTR_POSTAL_CODE,
        3},
    {0x55, 0x04, 0x11}},
    {{C509_ATTR_GIVEN_NAME,
        3},
    {0x55, 0x04, 0x2A}},
    {{C509_ATTR_INITIALS,
        3},
    {0x55, 0x04, 0x2B}},
    {{C509_ATTR_GENERATION_QUALIFIER,
        3},
    {0x55, 0x04, 0x2C}},
    {{C509_ATTR_DN_QUALIFIER,
        3},
    {0x55, 0x04, 0x2E}},
    {{C509_ATTR_PSEUDONYM,
        3},
    {0x55, 0x04, 0x41}},
    {{C509_ATTR_ORGANIZATION_IDENTIFIER,
        3},
    {0x55, 0x04, 0x61}},
    {{C509_ATTR_INC_LOCALITY,
        11},
    {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x01}},
    {{C509_ATTR_INC_STATE_OR_PROVINCE,
        11},
    {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x02}},
    {{C509_ATTR_INC_COUNTRY,
        11},
    {0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x3C, 0x02, 0x01, 0x03}},
    {{C509_ATTR_DOMAIN_COMPONENT,
        11},
    {0x0A, 0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19}},
};

C509_REGISTRY_ITERATOR_FUNCTION(c509_attribute_iterator,
                                c509_attribute_t,
                                c509_supported_attributes)

C509_REGISTRY_GET_BY_ID_FUNCTION(c509_attribute_get_by_id,
                                 c509_attribute_t,
                                 c509_attribute_id_t,
                                 c509_attribute_iterator)

C509_REGISTRY_GET_OID_FUNCTION(c509_attribute_get_oid,
                               c509_attribute_t)

static const struct {
    struct { c509_algorithm_parameters_t parameters; unsigned char null[2]; } _null;
    struct { c509_algorithm_parameters_t parameters; unsigned char _oid[8]; } _secp256r1;
    struct { c509_algorithm_parameters_t parameters; unsigned char _oid[5]; } _secp384r1;
    struct { c509_algorithm_parameters_t parameters; unsigned char _oid[5]; } _secp521r1;
} c509_supported_algorithm_parameters = {
    {{2}, {0x05, 0x00}},
    {{8}, {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}},
    {{5}, {0x2B, 0x81, 0x04, 0x00, 0x22}},
    {{5}, {0x2B, 0x81, 0x04, 0x00, 0x23}},
};

static const struct {
    struct { c509_pk_algorithm_t algorithm; unsigned char _oid[9]; } _rsa;
    struct { c509_pk_algorithm_t algorithm; unsigned char _oid[7]; } _ec_secp256r1;
    struct { c509_pk_algorithm_t algorithm; unsigned char _oid[7]; } _ec_secp384r1;
    struct { c509_pk_algorithm_t algorithm; unsigned char _oid[7]; } _ec_secp521r1;
} c509_supported_algorithms = {
    {{&c509_supported_algorithm_parameters._null.parameters,
        C509_PK_ALGORITHM_RSA,
            9},
    {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}},
    {{&c509_supported_algorithm_parameters._secp256r1.parameters,
        C509_PK_ALGORITHM_EC_SECP256R1,
            7},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}},
    {{&c509_supported_algorithm_parameters._secp384r1.parameters,
        C509_PK_ALGORITHM_EC_SECP384R1,
            7},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}},
    {{&c509_supported_algorithm_parameters._secp521r1.parameters,
        C509_PK_ALGORITHM_EC_SECP521R1,
            7},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}},
};

C509_REGISTRY_ITERATOR_FUNCTION(c509_pk_algorithm_iterator,
                                c509_pk_algorithm_t,
                                c509_supported_algorithms)

C509_REGISTRY_GET_BY_ID_FUNCTION(c509_pk_algorithm_get_by_id,
                                 c509_pk_algorithm_t,
                                 c509_pk_algorithm_id_t,
                                 c509_pk_algorithm_iterator)

C509_REGISTRY_GET_OID_FUNCTION(c509_pk_algorithm_get_oid,
                               c509_pk_algorithm_t)

C509_REGISTRY_GET_OID_FUNCTION(c509_algorithm_parameters_get_oid,
                               c509_algorithm_parameters_t)

bool c509_algorithm_parameters_is_null(const c509_algorithm_parameters_t *par)
{
    return par == (c509_algorithm_parameters_t *)
                  &c509_supported_algorithm_parameters._null;
}

bool c509_pk_is_rsa(c509_pk_algorithm_id_t id)
{
    switch (id) {
        case C509_PK_ALGORITHM_RSA: return true;
        default: return false;
    }
}

bool c509_pk_is_ec(c509_pk_algorithm_id_t id)
{
    switch (id) {
        case C509_PK_ALGORITHM_EC_SECP256R1: return true;
        case C509_PK_ALGORITHM_EC_SECP384R1: return true;
        case C509_PK_ALGORITHM_EC_SECP521R1: return true;
        default: return false;
    }
}

static const struct {
    struct { c509_extension_t extension; unsigned char _oid[3]; } _subject_key_identifier;
    struct { c509_extension_t extension; unsigned char _oid[3]; } _key_usage;
    struct { c509_extension_t extension; unsigned char _oid[3]; } _basic_constraints;
    struct { c509_extension_t extension; unsigned char _oid[3]; } _authority_key_identifier;
    struct { c509_extension_t extension; unsigned char _oid[8]; } _ip_resource;
} c509_supported_extensions = {
    {{C509_EXTENSION_SUBJECT_KEY_IDENTIFIER,
        3},
    {0x55, 0x1d, 0x0e}},
    {{C509_EXTENSION_KEY_USAGE,
        3},
    {0x55, 0x1d, 0x0f}},
    {{C509_EXTENSION_BASIC_CONSTRAIINTS,
        3},
    {0x55, 0x1d, 0x13}},
    {{C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,
        3},
    {0x55, 0x1d, 0x23}},
    {{C509_EXTENSION_IP_RESOURCE,
        8},
    {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x07}},
};

C509_REGISTRY_ITERATOR_FUNCTION(c509_extension_iterator,
                                c509_extension_t,
                                c509_supported_extensions)

C509_REGISTRY_GET_BY_ID_FUNCTION(c509_extension_get_by_id,
                                 c509_extension_t,
                                 c509_extension_id_t,
                                 c509_extension_iterator)

C509_REGISTRY_GET_OID_FUNCTION(c509_extension_get_oid,
                               c509_extension_t)

static const struct {
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[11]; } _rsassa_pkcs1_v15_with_sha1;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[7];  } _ecdsa_with_sha1;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[8];  } _ecdsa_with_sha256;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[8];  } _ecdsa_with_sha384;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[8];  } _ecdsa_with_sha512;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[11]; } _rsassa_pkcs1_v15_with_sha256;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[11]; } _rsassa_pkcs1_v15_with_sha384;
    struct { c509_sig_algorithm_t algorithm; uint8_t _oid[11]; } _rsassa_pkcs1_v15_with_sha512;
} c509_supported_signature_algorithms = {
    {{&c509_supported_algorithm_parameters._null.parameters,
        C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA1,
            11},
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00}},
    {{ALGORITHM_PARAMETERS_ABSENT,
        C509_SIG_ALGORITHM_ECDSA_WITH_SHA1,
            7},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01}},
    {{ALGORITHM_PARAMETERS_ABSENT,
        C509_SIG_ALGORITHM_ECDSA_WITH_SHA256,
            8},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}},
    {{ALGORITHM_PARAMETERS_ABSENT,
        C509_SIG_ALGORITHM_ECDSA_WITH_SHA384,
            8},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03}},
    {{ALGORITHM_PARAMETERS_ABSENT,
        C509_SIG_ALGORITHM_ECDSA_WITH_SHA512,
            8},
    {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04}},
    {{&c509_supported_algorithm_parameters._null.parameters,
        C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA256,
            9},
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B}},
    {{&c509_supported_algorithm_parameters._null.parameters,
        C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA384,
            9},
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C}},
    {{&c509_supported_algorithm_parameters._null.parameters,
        C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA512,
            9},
    {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D}},
};

C509_REGISTRY_ITERATOR_FUNCTION(c509_sig_algorithm_iterator,
                                c509_sig_algorithm_t,
                                c509_supported_signature_algorithms)

C509_REGISTRY_GET_BY_ID_FUNCTION(c509_sig_algorithm_get_by_id,
                                 c509_sig_algorithm_t,
                                 c509_sig_algorithm_id_t,
                                 c509_sig_algorithm_iterator)

C509_REGISTRY_GET_OID_FUNCTION(c509_sig_algorithm_get_oid,
                               c509_sig_algorithm_t)

bool c509_sig_is_rsa(const c509_sig_algorithm_id_t id)
{
    switch (id) {
        case C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA1: return true;
        case C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA256: return true;
        case C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA384: return true;
        case C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA512: return true;
        default: return false;
    }
}

bool c509_sig_is_ec(const c509_sig_algorithm_id_t id)
{
    switch (id) {
        case C509_SIG_ALGORITHM_ECDSA_WITH_SHA1: return true;
        case C509_SIG_ALGORITHM_ECDSA_WITH_SHA256: return true;
        case C509_SIG_ALGORITHM_ECDSA_WITH_SHA384: return true;
        case C509_SIG_ALGORITHM_ECDSA_WITH_SHA512: return true;
        default: return false;
    }
}

static inline bool _c509_writer_check(const c509_writer_t *writer)
{
    return writer && (writer->dst_end - writer->dst) > 0;
}

static inline bool _c509_reader_check(const c509_reader_t *reader)
{
    return reader && (reader->src_end - reader->src) > 0;
}

static inline int _c509_writer_array_start(c509_writer_t *writer)
{
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_array_indefinite(&enc)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

static inline int _c509_writer_array_finish(c509_writer_t *writer)
{
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_end_indefinite(&enc)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

static inline int _c509_reader_array_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    int ret;
    nanocbor_value_t dec, arr;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_enter_array(&dec, &arr)) < 0) {
        return ret;
    }
    iter->reader = reader;
    if (arr.flags & NANOCBOR_DECODER_FLAG_INDEFINITE) {
        iter->numof = -1;
    }
    else {
        iter->numof = arr.remaining;
    }
    ret = arr.cur - reader->src;
    reader->src += ret;
    return ret;
}

static inline int _c509_reader_array_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    nanocbor_value_t arr = dec;
    nanocbor_leave_container(&dec, &arr);
    int ret = dec.cur - reader->src;
    reader->src += ret;
    if (reader->src < reader->src_end && iter->numof < 0 && *reader->src == 0xff) {
        reader->src++;
        ret++;
    }
    return ret;
}


int c509_write_certificate_start(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_start(writer);
}

int c509_write_certificate_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_finish(writer);
}

int c509_write_type(c509_writer_t *writer,
                    c509_certificate_type_t type)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    if (type != C509_TYPE_DER && type != C509_TYPE_CBOR) {
        return -EINVAL;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, type)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += enc.len;
    return ret;
}

int c509_write_certificate_serial_number(c509_writer_t *writer,
                                         const uint8_t *serial,
                                         size_t serial_len)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    if (serial_len > 20) {
        return -EINVAL;
    }
    while (serial_len && !*serial) {
        serial_len--;
        serial++; /* skip leading zeros */
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_BIGNUMS_P)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_put_bstr(&enc, serial, serial_len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += enc.len;
    return ret;
}

int c509_write_name_start(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_start(writer);
}

int c509_write_name_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_finish(writer);
}

int c509_write_name_attribute_start(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_start(writer);
}

int c509_write_name_attribute_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_finish(writer);
}

int c509_write_name_attribute(c509_writer_t *writer,
                              const c509_name_attribute_t *attr)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (attr->printable_string ? -1 : 1) * attr->id)) < 0) {
        return ret;
    }
    if (attr->value && attr->value_len) {
        if ((ret = nanocbor_put_tstrn(&enc, (const char *)attr->value, attr->value_len)) != NANOCBOR_OK) {
            return ret;
        }
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_name_optimized(c509_writer_t *writer,
                              const uint8_t *common_name,
                              size_t len)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_put_tstrn(&enc, (const char *)common_name, len)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_validity(c509_writer_t *writer,
                        const c509_validity_t *validity)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_EPOCH)) < 0) {
        return ret;
    }
    if (validity->not_before >= VALIDITY_NO_EXPIRATION) {
        if ((ret = nanocbor_fmt_null(&enc)) != NANOCBOR_OK) {
            return ret;
        }
    }
    else if ((ret = nanocbor_fmt_int(&enc, validity->not_before)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_EPOCH)) < 0) {
        return ret;
    }
    if (validity->not_after >= VALIDITY_NO_EXPIRATION) {
        if ((ret = nanocbor_fmt_null(&enc)) != NANOCBOR_OK) {
            return ret;
        }
    }
    else if ((ret = nanocbor_fmt_int(&enc, validity->not_after)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_rsa_subject_public_key_info(c509_writer_t *writer,
                                          const c509_rsa_pk_info_t *pk_info)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, pk_info->id)) < 0) {
        return ret;
    }
    /* If the exponent is 65537, the array and the exponent is omitted */
    if (pk_info->exp_len == sizeof(_65537) && memcmp(pk_info->exponent, _65537, sizeof(_65537)) == 0) {
        if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_BIGNUMS_P)) < 0) {
            return ret;
        }
        if ((ret = nanocbor_put_bstr(&enc, pk_info->modulus, pk_info->mod_len)) < 0) {
            return ret;
        }
    }
    else {
        if ((ret = nanocbor_fmt_array(&enc, 2)) < 0) {
            return ret;
        }
        if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_BIGNUMS_P)) < 0) {
            return ret;
        }
        if ((ret = nanocbor_put_bstr(&enc, pk_info->modulus, pk_info->mod_len)) < 0) {
            return ret;
        }
        if ((ret = nanocbor_fmt_tag(&enc, NANOCBOR_TAG_BIGNUMS_P)) < 0) {
            return ret;
        }
        if ((ret = nanocbor_put_bstr(&enc, pk_info->exponent, pk_info->exp_len)) < 0) {
            return ret;
        }
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_ec_subject_public_key_info(c509_writer_t *writer,
                                          const c509_ec_pk_info_t *pk_info)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, pk_info->id)) < 0) {
        return ret;
    }
    uint8_t ec_compression;
    size_t ec_len = pk_info->len;
    if (pk_info->point[0] == 0x04) {
        if (pk_info->point[pk_info->len - 1] & 1) {
            ec_compression = 0xfd;
        }
        else {
            ec_compression = 0xfe;
        }
        ec_len = 1 + (pk_info->len / 2);

    }
    else if (pk_info->point[0] == 0x03) {
        ec_compression = 0xfd;
    }
    else if (pk_info->point[0] == 0x02) {
        ec_compression = 0xfe;
    }
    else {
        return -EINVAL;
    }
    if ((ret = nanocbor_fmt_bstr(&enc, ec_len)) < 0) {
        return ret;
    }
    if ((size_t)(enc.end - enc.cur) < ec_len) {
        return -ENOBUFS;
    }
    *enc.cur++ = ec_compression;
    enc.len++;
    memcpy(enc.cur, pk_info->point + 1, ec_len = (ec_len - 1));
    enc.cur += ec_len;
    enc.len += ec_len;
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extensions_start(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_start(writer);
}

int c509_write_extensions_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_finish(writer);
}

int c509_write_extension_subject_key_identifier(c509_writer_t *writer,
                                                const c509_extension_subject_key_identifier_t *ski)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (ski->extension.critical ? -1 : 1) * C509_EXTENSION_SUBJECT_KEY_IDENTIFIER)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_put_bstr(&enc, ski->identifier, ski->identifier_len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_authority_key_identifier(c509_writer_t *writer,
                                                  const c509_extension_authority_key_identifier_t *aki)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (aki->extension.critical ? -1 : 1) * C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_put_bstr(&enc, aki->identifier, aki->identifier_len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_basic_constraints(c509_writer_t *writer,
                                           const c509_extension_basic_constraints_t *bc)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (bc->extension.critical ? -1 : 1) * C509_EXTENSION_BASIC_CONSTRAIINTS)) < 0) {
        return ret;
    }
    if (!bc->ca) {
        if ((ret = nanocbor_fmt_int(&enc, -2)) < 0) {
            return ret;
        }
    }
    else if (bc->pathlen < 0) {
        if ((ret = nanocbor_fmt_int(&enc, -1)) < 0) {
            return ret;
        }
    }
    else {
        if ((ret = nanocbor_fmt_int(&enc, bc->pathlen)) < 0) {
            return ret;
        }
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_key_usage(c509_writer_t *writer,
                                   const c509_extension_key_usage_t *ku)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (ku->extension.critical ? -1 : 1) * C509_EXTENSION_KEY_USAGE)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_fmt_int(&enc, ku->usage)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_key_usage_optimized(c509_writer_t *writer,
                                             const c509_extension_key_usage_t *ku)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    assert(ku->usage >= 0);
    if ((ret = nanocbor_fmt_int(&enc, (ku->extension.critical ? -1 : 1) * ku->usage)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_ip_resource_start(c509_writer_t *writer,
                                           const c509_extension_ip_resource_t *ipr)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, (ipr->extension.critical ? -1 : 1) * C509_EXTENSION_IP_RESOURCE)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_fmt_array(&enc, 2)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_fmt_uint(&enc, 2)) < 0) { /* AFI = 2 means IPv6 */
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_ip_resource_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return 0;
}

int c509_write_extension_ip_resource_null_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_null(&enc)) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_ip_resource_address_or_range_start(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_start(writer);
}

int c509_write_extension_ip_resource_address_or_range_finish(c509_writer_t *writer)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    return _c509_writer_array_finish(writer);
}

int c509_write_extension_ip_resource_prefix(c509_writer_t *writer,
                                            const c509_extension_ip_resource_prefix_t *pfx)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_put_bstr(&enc, pfx->addr, (pfx->len + 7) / 8)) != NANOCBOR_OK) {
        return ret;
    }
    if ((ret = nanocbor_fmt_uint(&enc, (8 - (pfx->len % 8)) % 8)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_extension_ip_resource_range(c509_writer_t *writer,
                                           const c509_extension_ip_resource_range_t *rg)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
/* Each AddressRange is encoded as an array of two CBOR byte strings.
   The unused bits for min and max are omitted, but the unused bits in max IPAddress is set to ones.
   With the exception of the first Address, if the byte string has the same length as the previous ASid,
   the Addess is encoded as an uint with the the difference to the previous Addess.
   - I don´t understand this :/ */
    if ((ret = nanocbor_fmt_array(&enc, 2)) < 0) {
        return ret;
    }
    if ((ret = nanocbor_put_bstr(&enc, rg->min, sizeof(rg->min))) != NANOCBOR_OK) {
        return ret;
    }
    if ((ret = nanocbor_put_bstr(&enc, rg->max, sizeof(rg->max))) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_signature_algorithm(c509_writer_t *writer,
                                   c509_sig_algorithm_id_t id)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_fmt_int(&enc, id)) < 0) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_signature_rsa(c509_writer_t *writer,
                             const c509_signature_rsa_t *sig)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    if ((ret = nanocbor_put_bstr(&enc, sig->value, sig->len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_write_signature_ecdsa(c509_writer_t *writer,
                            const c509_signature_ecdsa_t *sig)
{
    if (!_c509_writer_check(writer)) {
        return -ENOBUFS;
    }
    int ret;
    nanocbor_encoder_t enc;
    nanocbor_encoder_init(&enc, writer->dst, writer->dst_end - writer->dst);
    size_t max = sig->r_len > sig->s_len ? sig->r_len : sig->s_len;
    if ((ret = nanocbor_fmt_bstr(&enc, 2 * max)) < 0) {
        return ret;
    }
    if ((size_t)(enc.end - enc.cur) < 2 * max) {
        return -ENOBUFS;
    }
    while (sig->r_len < sig->s_len) {
        *enc.cur++ = 0x00;
        enc.len++;
    }
    memcpy(enc.cur, sig->r, sig->r_len);
    enc.cur += sig->r_len;
    enc.len += sig->r_len;
    while (sig->s_len < sig->r_len) {
        *enc.cur++ = 0x00;
        enc.len++;
    }
    memcpy(enc.cur, sig->s, sig->s_len);
    enc.cur += sig->s_len;
    enc.len += sig->s_len;
    ret = enc.cur - writer->dst;
    writer->dst += ret;
    return ret;
}

int c509_read_certificate_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_start(reader, iter);
}

int c509_read_certificate_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}

int c509_read_version(c509_reader_t *reader, int *version)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int8_t v;
    if ((ret = nanocbor_get_int8(&dec, &v)) < 0) {
        return ret;
    }
    if (v != C509_TYPE_CBOR && v != C509_TYPE_DER) {
        return -ENOTSUP;
    }
    *version = v;
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_serial(c509_reader_t *reader, const uint8_t **serial, size_t *serial_len)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    uint32_t tag;
    if ((ret = nanocbor_get_tag(&dec, &tag)) != NANOCBOR_OK) {
        return ret;
    }
    if (tag != NANOCBOR_TAG_BIGNUMS_P) {
        return -ENOTSUP;
    }
    if ((ret = nanocbor_get_bstr(&dec, serial, serial_len)) != NANOCBOR_OK) {
        return ret;
    }
    if (*serial_len > 20) {
        return -ENOTSUP;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_name_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_start(reader, iter);
}

int c509_read_name_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}

int c509_read_name_next(c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(iter->reader)) {
        return -EINVAL;
    }
    if (iter->numof == 0 || (iter->numof < 0 && *iter->reader->src == 0xff)) {
        return 0;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, iter->reader->src, 1);
    switch (nanocbor_get_type(&dec)) {
        case NANOCBOR_TYPE_ARR:
            return iter->numof > 0 ? iter->numof-- : 1;
    }
    return -ENOTSUP;
}

int c509_read_name_attribute_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_start(reader, iter);
}

int c509_read_name_attribute_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}


int c509_read_name_attribute_next(c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(iter->reader)) {
        return -EINVAL;
    }
    if (iter->numof == 0 || (iter->numof < 0 && *iter->reader->src == 0xff)) {
        return 0;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, iter->reader->src, 1);
    switch (nanocbor_get_type(&dec)) {
        case NANOCBOR_MASK_UINT:
        case NANOCBOR_TYPE_NINT:
            return iter->numof > 0 ? iter->numof-- : 1;
    }
    return -ENOTSUP;
}

int c509_read_name_attribute(c509_reader_t *reader, c509_name_attribute_t *attribute)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int16_t attr_id;
    const uint8_t *cn;
    size_t cn_len;
    if ((ret = nanocbor_get_int16(&dec, &attr_id)) < 1) {
        return ret;
    }
    if ((ret = nanocbor_get_tstr(&dec, &cn, &cn_len)) != NANOCBOR_OK) {
        return ret;
    }
    if (attribute) {
        *attribute = (c509_name_attribute_t){
            .id = attr_id < 0 ? -attr_id : attr_id,
            .printable_string = attr_id < 0,
            .value = cn,
            .value_len = cn_len
        };
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_name(c509_reader_t *reader, c509_name_attribute_t *name, unsigned *max)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    unsigned m = *max;
    const uint8_t *start = reader->src;
    c509_array_iterator_t name_iter;
    if ((ret = c509_read_name_optimized(reader, m > 0 ? name : NULL)) > 0) {
        if (m > 0) {
            m--;
            name++;
        }
    }
    else {
        if ((ret = c509_read_name_start(reader, &name_iter)) < 0) {
            return ret;
        }
        if (c509_read_name_next(&name_iter) > 0) {
            while (c509_read_name_next(&name_iter) > 0) {
                c509_array_iterator_t name_attr_iter;
                if ((ret = c509_read_name_attribute_start(reader, &name_attr_iter)) < 0) {
                    return ret;
                }
                while ((c509_read_name_attribute_next(&name_iter)) > 0) {
                    if ((ret = c509_read_name_attribute(reader, m > 0 ? name : NULL)) < 0) {
                        return ret;
                    }
                    if (m > 0) {
                        m--;
                        name++;
                    }
                }
                if ((ret = c509_read_name_attribute_finish(reader, &name_iter)) < 0) {
                    return ret;
                }
            }
        }
        else {
            while ((c509_read_name_attribute_next(&name_iter)) > 0) {
                if ((ret = c509_read_name_attribute(reader, m > 0 ? name : NULL)) < 0) {
                    return ret;
                }
                if (m > 0) {
                    m--;
                    name++;
                }
            }
        }
        if ((ret = c509_read_name_finish(reader, &name_iter)) < 0) {
            return ret;
        }
    }
    *max -= m;
    return reader->src - start;;
}

int c509_read_name_optimized(c509_reader_t *reader, c509_name_attribute_t *name) {
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    const uint8_t *cn;
    size_t cn_len;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_tstr(&dec, &cn, &cn_len)) < 0) {
        return ret;
    }
    if (name) {
        *name = (c509_name_attribute_t){
            .id = C509_ATTR_COMMON_NAME,
            .printable_string = false,
            .value = cn,
            .value_len = cn_len,
        };
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_validity(c509_reader_t *reader, c509_validity_t *validity)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    uint32_t tag;
    if ((ret = nanocbor_get_null(&dec)) == NANOCBOR_OK) {
        validity->not_before = VALIDITY_NO_EXPIRATION;
    }
    else {
        if (((ret = nanocbor_get_tag(&dec, &tag)) != NANOCBOR_OK) ||
            (tag != NANOCBOR_TAG_EPOCH)) {
            return ret;
        }
        if ((ret = nanocbor_get_uint64(&dec, (uint64_t *)&validity->not_before)) < 1) {
            return ret;
        }
    }
    if ((ret = nanocbor_get_null(&dec)) == NANOCBOR_OK) {
        validity->not_after = VALIDITY_NO_EXPIRATION;
    }
    else {
        if (((ret = nanocbor_get_tag(&dec, &tag)) != NANOCBOR_OK) ||
            (tag != NANOCBOR_TAG_EPOCH)) {
            return ret;
        }
        if ((ret = nanocbor_get_uint64(&dec, (uint64_t *)&validity->not_after)) < 1) {
            return ret;
        }
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_subject_public_key_info(c509_reader_t *reader, c509_pk_info_t *pki)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int16_t pk_id;
    if ((ret = nanocbor_get_int16(&dec, &pk_id)) < 1) {
        return ret;
    }
    if (c509_pk_is_rsa(pk_id)) {
        nanocbor_value_t arr;
        uint32_t tag;
        if ((ret = nanocbor_enter_array(&dec, &arr)) == NANOCBOR_OK) {
            if (((ret = nanocbor_get_tag(&arr, &tag)) != NANOCBOR_OK) ||
                (tag != NANOCBOR_TAG_BIGNUMS_P)) {
                return -ENOTSUP;
            }
            if ((ret = nanocbor_get_bstr(&arr, &pki->rsa.modulus, &pki->rsa.mod_len)) != NANOCBOR_OK) {
                return ret;
            }
            if (((ret = nanocbor_get_tag(&arr, &tag)) != NANOCBOR_OK) ||
                (tag != NANOCBOR_TAG_BIGNUMS_P)) {
                return -ENOTSUP;
            }
            if ((ret = nanocbor_get_bstr(&arr, &pki->rsa.exponent, &pki->rsa.exp_len)) != NANOCBOR_OK) {
                return ret;
            }
            pki->rsa.id = pk_id;
            nanocbor_leave_container(&dec, &arr);
        }
        else if (((ret = nanocbor_get_tag(&dec, &tag)) == NANOCBOR_OK) &&
                 (tag == NANOCBOR_TAG_BIGNUMS_P)) {
            pki->rsa.exponent = _65537;
            pki->rsa.exp_len = sizeof(_65537);
            if ((ret = nanocbor_get_bstr(&dec, &pki->rsa.modulus, &pki->rsa.mod_len)) != NANOCBOR_OK) {
                return ret;
            }
            pki->rsa.id = pk_id;
        }
        else {
            return -ENOTSUP;
        }
    }
    else if (c509_pk_is_ec(pk_id)) {
        if ((ret = nanocbor_get_bstr(&dec, &pki->ec.point, &pki->ec.len)) != NANOCBOR_OK) {
            return ret;
        }
        pki->ec.id = pk_id;
    }
    else {
        return -ENOTSUP;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extensions_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_start(reader, iter);
}

int c509_read_extensions_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}

int c509_read_extension(c509_reader_t *reader, c509_extension_base_t *extension)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int16_t extn_id;
    if ((ret = nanocbor_get_int16(&dec, &extn_id)) < 1) {
        return ret;
    }
    *extension = (c509_extension_base_t){
        .id = extn_id < 0 ? -extn_id : extn_id,
        .critical = extn_id < 0,
    };
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_extension_iterator_next(c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(iter->reader)) {
        return -EINVAL;
    }
    if (iter->numof == 0 || (iter->numof < 0 && *iter->reader->src == 0xff)) {
        return 0;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, iter->reader->src, 1);
    switch (nanocbor_get_type(&dec)) {
        case NANOCBOR_MASK_UINT:
        case NANOCBOR_TYPE_NINT:
            return iter->numof > 0 ? iter->numof-- : 1;
    }
    return -ENOTSUP;
}

int c509_read_extension_subject_key_identifier(c509_reader_t *reader, c509_extension_subject_key_identifier_t *ski)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    if (ski->extension.id != C509_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
        if ((ret = c509_read_extension(reader, &ski->extension)) < 0) {
            return ret;
        }
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_bstr(&dec, &ski->identifier, &ski->identifier_len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_key_usage(c509_reader_t *reader, c509_extension_key_usage_t *ku)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    if (ku->extension.id != C509_EXTENSION_KEY_USAGE) {
        if ((ret = c509_read_extension(reader, &ku->extension)) < 0) {
            return ret;
        }
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_int16(&dec, (int16_t *)&ku->usage)) < 1) {
        return ret;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_key_usage_optimized(c509_reader_t *reader, c509_extension_key_usage_t *ku)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    /* If the array contains exactly two ints and the absolute value of the first int is 2
       (corresponding to keyUsage), the array is omitted and the extensions is encoded as
       a single CBOR int with the absolute value of the second int and the sign of the
       first int. */
    int ret;
    int16_t opt;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_int16(&dec, &opt)) < 1) {
        return ret;
    }
    *ku = (c509_extension_key_usage_t){
        .extension = {
            .critical = opt < 0,
            .id = C509_EXTENSION_KEY_USAGE
        },
        .usage = opt < 0 ? -opt : opt
    };
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_authority_key_identifier(c509_reader_t *reader, c509_extension_authority_key_identifier_t *aki)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    if (aki->extension.id != C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) {
        if ((ret = c509_read_extension(reader, &aki->extension)) < 0) {
            return ret;
        }
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    nanocbor_value_t arr;
    if ((ret = nanocbor_enter_array(&dec, &arr)) == NANOCBOR_OK) {
        return -ENOTSUP; /* not implemented */
    }
    else if ((ret = nanocbor_get_bstr(&dec, &aki->identifier, &aki->identifier_len)) != NANOCBOR_OK) {
        return ret;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_basic_constraints(c509_reader_t *reader, c509_extension_basic_constraints_t *bc)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    if (bc->extension.id != C509_EXTENSION_BASIC_CONSTRAIINTS) {
        if ((ret = c509_read_extension(reader, &bc->extension)) < 0) {
            return ret;
        }
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int8_t value;
    if ((ret = nanocbor_get_int8(&dec, &value)) < 1) {
        return ret;
    }
    bc->pathlen = -1;
    if (value == -2) {
        bc->ca = false;
    }
    else if (value == -1) {
        bc->ca = true;
    }
    else if (value < 0) {
        return -EINVAL;
    }
    else {
        bc->ca = true;
        bc->pathlen = value;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_ip_resource_start(c509_reader_t *reader, c509_array_iterator_t *iter, c509_extension_ip_resource_t *ip)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    if (ip->extension.id != C509_EXTENSION_IP_RESOURCE) {
        if ((ret = c509_read_extension(reader, &ip->extension)) < 0) {
            return ret;
        }
    }
    if ((ret = _c509_reader_array_start(reader, iter)) < 0) {
        return ret;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((c509_read_extension_ip_resource_next(iter)) <= 0) {
        return -ENOTSUP;
    }
    uint8_t afi;
    if ((ret = nanocbor_get_uint8(&dec, &afi)) < 1) {
        return afi;
    }
    if (afi != 2) {
        return -ENOTSUP;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extension_ip_resource_next(c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(iter->reader)) {
        return -EINVAL;
    }
    if (iter->numof == 0 || (iter->numof < 0 && *iter->reader->src == 0xff)) {
        return 0;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, iter->reader->src, iter->reader->src_end - iter->reader->src);
    switch (nanocbor_get_type(&dec)) {
        case NANOCBOR_TYPE_UINT:
        case NANOCBOR_TYPE_ARR:
        case NANOCBOR_TYPE_FLOAT: /* simple value NULL */
            return iter->numof > 0 ? iter->numof-- : 1;
    }
    return -ENOTSUP;
}

int c509_read_extension_ip_resource_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}

 int c509_read_extension_ip_resource_null(c509_reader_t *reader, c509_extension_ip_range_or_prefix_t *range_or_prefix)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_null(&dec)) == NANOCBOR_OK) {
        range_or_prefix->type = C509_EXTENSION_IP_RESOURCE_NULL;
        ret = dec.cur - reader->src;
        reader->src += ret;
        return ret;
    }
    return 0;
}

int c509_read_extension_ip_resource_address_or_range_start(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_start(reader, iter);
}

int c509_read_extension_ip_resource_address_or_range_next(c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(iter->reader)) {
        return -EINVAL;
    }
    if (iter->numof == 0 || (iter->numof < 0 && *iter->reader->src == 0xff)) {
        return 0;
    }
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, iter->reader->src, iter->reader->src_end - iter->reader->src);
    switch (nanocbor_get_type(&dec)) {
        case NANOCBOR_TYPE_BSTR:
        case NANOCBOR_TYPE_ARR:
            return iter->numof > 0 ? iter->numof-- : 1;
    }
    return -ENOTSUP;
}

int c509_read_extension_ip_resource_address_or_range_finish(c509_reader_t *reader, c509_array_iterator_t *iter)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    return _c509_reader_array_finish(reader, iter);
}

int c509_read_extension_ip_resource(c509_reader_t *reader, c509_extension_ip_range_or_prefix_t *range_or_prefix)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    size_t size;
    const uint8_t *ptr;
    nanocbor_value_t dec, arr;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_bstr(&dec, &ptr, &size)) == NANOCBOR_OK) {
        uint8_t unused;
        if ((ret = nanocbor_get_uint8(&dec, &unused)) < 1) {
            return ret;
        }
        if (size > sizeof(range_or_prefix->res.prefix.addr) || unused > 7) {
            return -ENOTSUP;
        }
        memset(range_or_prefix->res.prefix.addr, 0, sizeof(range_or_prefix->res.prefix.addr));
        memcpy(range_or_prefix->res.prefix.addr, ptr, size);
        range_or_prefix->res.prefix.len = 8 * size - unused;
        range_or_prefix->type = C509_EXTENSION_IP_RESOURCE_PREFIX;
    }
    else if ((ret = nanocbor_enter_array(&dec, &arr)) == NANOCBOR_OK) {
        if ((ret = nanocbor_get_bstr(&arr, &ptr, &size)) != NANOCBOR_OK) {
            return ret;
        }
        if (size > sizeof(range_or_prefix->res.range.min)) {
            return -ENOTSUP;
        }
        memset(range_or_prefix->res.range.min, 0, sizeof(range_or_prefix->res.range.min));
        memcpy(range_or_prefix->res.range.min, ptr, size);
        if ((ret = nanocbor_get_bstr(&arr, &ptr, &size)) != NANOCBOR_OK) {
            return ret;
        }
        if (size > sizeof(range_or_prefix->res.range.max)) {
            return -ENOTSUP;
        }
        memset(range_or_prefix->res.range.max + size, 0xff, sizeof(range_or_prefix->res.range.max) - size);
        memcpy(range_or_prefix->res.range.max, ptr, size);
        range_or_prefix->type = C509_EXTENSION_IP_RESOURCE_RANGE;
        nanocbor_leave_container(&dec, &arr);
    }
    else {
        return -ENOTSUP;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_extensions_next(c509_reader_t *reader, c509_array_iterator_t *iter,
                              void *extn_type, size_t size,
                              int (*extn_cb)(void * extn, size_t size))
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    const uint8_t *start = reader->src;
    if (c509_extension_iterator_next(iter) > 0) {
        if (size < sizeof(c509_extension_base_t)) {
            return -ENOBUFS;
        }
        c509_extension_base_t *extension = extn_type;
        if ((ret = c509_read_extension(reader, extn_type)) < 0) {
            return ret;
        }
        if (extension->id == C509_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
            if (size < sizeof(c509_extension_subject_key_identifier_t)) {
                return -ENOBUFS;
            }
            if ((ret = c509_read_extension_subject_key_identifier(reader,
                        (c509_extension_subject_key_identifier_t *)extn_type)) < 0) {
                return ret;
            }
        }
        else if (extension->id == C509_EXTENSION_KEY_USAGE) {
            if (size < sizeof(c509_extension_key_usage_t)) {
                return -ENOBUFS;
            }
            if ((ret = c509_read_extension_key_usage(reader,
                        (c509_extension_key_usage_t *)extn_type)) < 0) {
                return ret;
            }
        }
        else if (extension->id == C509_EXTENSION_BASIC_CONSTRAIINTS) {
            if (size < sizeof(c509_extension_basic_constraints_t)) {
                return -ENOBUFS;
            }
            if ((ret = c509_read_extension_basic_constraints(reader,
                        (c509_extension_basic_constraints_t *)extn_type)) < 0) {
                return ret;
            }
        }
        else if (extension->id == C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) {
            if (size < sizeof(c509_extension_authority_key_identifier_t)) {
                return -ENOBUFS;
            }
            if ((ret = c509_read_extension_authority_key_identifier(reader,
                        (c509_extension_authority_key_identifier_t *)extn_type)) < 0) {
                return ret;
            }
        }
        else if (extension->id == C509_EXTENSION_IP_RESOURCE) {
            if (size < sizeof(c509_extension_ip_resource_vla_x_t(1))) {
                return -ENOBUFS;
            }
            c509_extension_ip_resource_vla_t *ip = (c509_extension_ip_resource_vla_t *)extn_type;
            c509_extension_ip_range_or_prefix_t *range_or_prefix = ip->range_or_prefix;
            c509_array_iterator_t ip_res_iter;
            if ((ret = c509_read_extension_ip_resource_start(reader, &ip_res_iter, &ip->ip)) < 0) {
                return ret;
            }
            if ((ret = c509_read_extension_ip_resource_next(&ip_res_iter)) <= 0) {
                return -ENOTSUP;
            }
            if ((ret = c509_read_extension_ip_resource_null(reader, range_or_prefix)) <= 0) {
                c509_array_iterator_t addr_range_iter;
                if ((ret = c509_read_extension_ip_resource_address_or_range_start(reader, &addr_range_iter)) < 0) {
                    return ret;
                }
                ip->ip.numof = 0;
                while (c509_read_extension_ip_resource_address_or_range_next(&addr_range_iter) > 0) {
                    if ((uint8_t *)(&range_or_prefix[1]) > (((uint8_t *)(extn_type)) + size)) {
                        return -ENOBUFS;
                    }
                    if ((ret = c509_read_extension_ip_resource(reader, range_or_prefix)) < 0) {
                        return ret;
                    }
                    range_or_prefix++;
                    ip->ip.numof++;
                }
                if (ip->ip.numof == 0) {
                    return -ENOTSUP;
                }
                if ((ret = c509_read_extension_ip_resource_address_or_range_finish(reader, &addr_range_iter)) < 0) {
                    return ret;
                }
            }
            else {
                ip->ip.numof = 1; /* NULL */
            }
            if ((ret = c509_read_extension_ip_resource_next(&ip_res_iter)) > 0) {
                return -ENOTSUP;
            }
            if ((ret = c509_read_extension_ip_resource_finish(reader, &ip_res_iter)) < 0) {
                return ret;
            }
        }
        else {
            if (!extn_cb || extn_cb(extn_type, reader->src_end - reader->src) < 0) {
                return -ENOTSUP;
            }
        }
    }
    return reader->src - start;
}

int c509_read_extensions(c509_reader_t *reader, c509_extensions_t *extn)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    const uint8_t *start = reader->src;
    if ((ret = c509_read_extension_key_usage_optimized(reader, &extn->ku) < 0)) {
        c509_array_iterator_t extn_iter;
        if ((ret = c509_read_extensions_start(reader, &extn_iter)) < 0) {
            return ret;
        }
        do {
            c509_extension_base_t extension = { .id = 0 };
            c509_reader_t tmp_reader = *reader;
            if ((ret = c509_read_extensions_next(&tmp_reader, &extn_iter,
                                                 &extension, sizeof(extension), NULL)) < 0) {
                if (extension.id != 0 && ret == -ENOBUFS) {
                    if (extension.id == C509_EXTENSION_SUBJECT_KEY_IDENTIFIER) {
                        if ((ret = c509_read_extensions_next(reader, &extn_iter,
                                                             &extn->ski.extension, sizeof(extn->ski), NULL)) < 0) {
                            return ret;
                        }
                    }
                    else if (extension.id == C509_EXTENSION_KEY_USAGE) {
                        if ((ret = c509_read_extensions_next(reader, &extn_iter,
                                                             &extn->ku.extension, sizeof(extn->ku), NULL)) < 0) {
                            return ret;
                        }
                    }
                    else if (extension.id == C509_EXTENSION_BASIC_CONSTRAIINTS) {
                        if ((ret = c509_read_extensions_next(reader, &extn_iter,
                                                             &extn->bc.extension, sizeof(extn->bc), NULL)) < 0) {
                            return ret;
                        }
                    }
                    else if (extension.id == C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) {
                        if ((ret = c509_read_extensions_next(reader, &extn_iter,
                                                             &extn->aki.extension, sizeof(extn->aki), NULL)) < 0) {
                            return ret;
                        }
                    }
                    else if (extension.id == C509_EXTENSION_IP_RESOURCE) {
                        if ((ret = c509_read_extensions_next(reader, &extn_iter,
                                                             &extn->ip.ip.extension, sizeof(extn->ip.ip.extension), NULL)) < 0) {
                            return ret;
                        }
                    }
                    else {
                        return -ENOTSUP;
                    }
                }
                else {
                    return ret;
                }
            }
        } while (ret != 0 && ret != -ENOTSUP);
        if ((ret = c509_read_extensions_finish(reader, &extn_iter)) < 0) {
            return ret;
        }
    }
    return reader->src - start;
}

int c509_read_signature_algorithm(c509_reader_t *reader, c509_sig_algorithm_id_t *sig_id)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    int32_t id;
    if ((ret = nanocbor_get_int32(&dec, &id)) < 0) {
        return ret;
    }
    *sig_id = id;
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_signature_rsa(c509_reader_t *reader, c509_signature_rsa_t *signature)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_bstr(&dec, &signature->value, &signature->len)) < 0) {
        return ret;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_signature_ecdsa(c509_reader_t *reader, c509_signature_ecdsa_t *signature)
{
    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    nanocbor_value_t dec;
    nanocbor_decoder_init(&dec, reader->src, reader->src_end - reader->src);
    if ((ret = nanocbor_get_bstr(&dec, &signature->r, &signature->r_len)) != NANOCBOR_OK) {
        return ret;
    }
    signature->s = signature->r + (signature->r_len / 2);
    signature->s_len = signature->r_len = signature->r_len / 2;
    while (signature->r_len && *signature->r == 0x00) {
        signature->r++;
        signature->r_len--;
    }
    while (signature->s_len && *signature->s == 0x00) {
        signature->s++;
        signature->s_len--;
    }
    ret = dec.cur - reader->src;
    reader->src += ret;
    return ret;
}

int c509_read_signature(c509_reader_t *reader, c509_signature_t *signature)
{

    if (!_c509_reader_check(reader)) {
        return -EINVAL;
    }
    int ret;
    const uint8_t *start = reader->src;
    if ((ret = c509_read_signature_algorithm(reader, &signature->id)) < 0) {
        return ret;
    }
    if (c509_sig_is_ec(signature->id)) {
        if ((ret = c509_read_signature_ecdsa(reader, &signature->ecdsa)) < 0) {
            return ret;
        }
    }
    else if (c509_sig_is_rsa(signature->id)){
        if ((ret = c509_read_signature_rsa(reader, &signature->rsa)) < 0) {
            return ret;
        }
    }
    return reader->src - start;
}

void c509_init_certificate(c509_crt_t *c509, void *buf, size_t size)
{
    assert(buf);
    uint8_t *aligned_buf = ((uint8_t *)buf) + (sizeof(uintptr_t) - 1);
    aligned_buf = (uint8_t *)(((uintptr_t)aligned_buf) & ~((uintptr_t)(sizeof(uintptr_t) - 1)));
    assert(size > sizeof(uintptr_t));
    size -= (aligned_buf - ((uint8_t *)buf));
    size &= ~((size_t)(sizeof(uintptr_t) - 1));
    memset(c509, 0, sizeof(*c509));
    c509->buf = aligned_buf;
    c509->buf_size = size;
    memset(c509->buf, 0, c509->buf_size);
}

int c509_parse_certificate(c509_crt_t *c509, const void *buf, size_t size)
{
    assert(buf);
    assert(!(((uintptr_t)buf) & (sizeof(uintptr_t) - 1)));
    assert(!(size & (sizeof(uintptr_t) - 1)));
    int ret;
    c509_reader_t reader = C509_READER_INITIALIZER(buf, ((uint8_t *)buf) + size);
    c509_array_iterator_t cert_iter;
    if ((ret = c509_read_certificate_start(&reader, &cert_iter)) < 0) {
        return ret;
    }
    if ((ret = c509_read_version(&reader, &c509->type)) < 0) {
        return ret;
    }
    if ((ret = c509_read_serial(&reader, &c509->serial, &size)) < 0) {
        return ret;
    }
    c509->serial_len = size;
    c509->issuer = (c509_name_attribute_t *)c509->buf;
    unsigned name_max = c509->buf_size / sizeof(*c509->issuer);
    if ((ret = c509_read_issuer(&reader, c509->issuer, &name_max)) < 0) {
        return ret;
    }
    size = name_max * sizeof(*c509->issuer);
    c509->buf_size -= size;
    c509->buf = ((uint8_t *)(c509->buf)) + size;
    if ((ret = c509_read_validity(&reader, &c509->validity)) < 0) {
        return ret;
    }
    c509->subject = (c509_name_attribute_t *)c509->buf;
    name_max = c509->buf_size / sizeof(*c509->subject);
    if ((ret = c509_read_subject(&reader, c509->subject, &name_max)) < 0) {
        return ret;
    }
    size = name_max * sizeof(*c509->subject);
    c509->buf_size -= (name_max * sizeof(*c509->subject));
    c509->buf = ((uint8_t *)(c509->buf)) + size;
    if ((ret = c509_read_subject_public_key_info(&reader, &c509->subject_public_key)) < 0) {
        return ret;
    }
    memset(&c509->extensions, 0, sizeof(c509->extensions));
    if ((ret = c509_read_extensions(&reader, &c509->extensions)) < 0) {
        return ret;
    }
    if ((ret = c509_read_signature(&reader, &c509->signature)) < 0) {
        return ret;
    }
    if ((ret = c509_read_certificate_finish(&reader, &cert_iter)) < 0) {
        return ret;
    }
    return 0;
}
