#ifndef C509_H
#define C509_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdalign.h>

#ifdef __cplusplus
extern "C" {
#endif

#define C509_ATTR_EMAIL                                     0
#define C509_ATTR_COMMON_NAME                               1
#define C509_ATTR_SURNAME                                   2
#define C509_ATTR_SERIAL_NUMBER                             3
#define C509_ATTR_COUNTRY                                   4
#define C509_ATTR_LOCALITY                                  5
#define C509_ATTR_STATE_OR_PROVINCE                         6
#define C509_ATTR_STREET_ADDRESS                            7
#define C509_ATTR_ORGANIZATION                              8
#define C509_ATTR_ORGANIZATION_UNIT                         9
#define C509_ATTR_TITLE                                     10
#define C509_ATTR_BUSINESS_CATEGORY                         11
#define C509_ATTR_POSTAL_CODE                               12
#define C509_ATTR_GIVEN_NAME                                13
#define C509_ATTR_INITIALS                                  14
#define C509_ATTR_GENERATION_QUALIFIER                      15
#define C509_ATTR_DN_QUALIFIER                              16
#define C509_ATTR_PSEUDONYM                                 17
#define C509_ATTR_ORGANIZATION_IDENTIFIER                   18
#define C509_ATTR_INC_LOCALITY                              19
#define C509_ATTR_INC_STATE_OR_PROVINCE                     20
#define C509_ATTR_INC_COUNTRY                               21
#define C509_ATTR_DOMAIN_COMPONENT                          22

#define C509_PK_ALGORITHM_RSA                               0
#define C509_PK_ALGORITHM_EC_SECP256R1                      1
#define C509_PK_ALGORITHM_EC_SECP384R1                      2
#define C509_PK_ALGORITHM_EC_SECP521R1                      3
/* don´t care to support all algorithms right now */

#define C509_EXTENSION_SUBJECT_KEY_IDENTIFIER               1
#define C509_EXTENSION_KEY_USAGE                            2
#define C509_EXTENSION_BASIC_CONSTRAIINTS                   4
#define C509_EXTENSION_AUTHORITY_KEY_IDENTIFIER             7
#define C509_EXTENSION_IP_RESOURCE                          32
/* don´t care to support all extensions right now */

#define C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA1       -256
#define C509_SIG_ALGORITHM_ECDSA_WITH_SHA1                  -255
#define C509_SIG_ALGORITHM_ECDSA_WITH_SHA256                0
#define C509_SIG_ALGORITHM_ECDSA_WITH_SHA384                1
#define C509_SIG_ALGORITHM_ECDSA_WITH_SHA512                2
#define C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA256     23
#define C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA384     24
#define C509_SIG_ALGORITHM_RSASSA_PKCS1_V15_WITH_SHA512     25
/* don´t care to support all algorithms right now */

typedef struct {
    uint8_t *dst;
    const uint8_t *dst_end;
} c509_writer_t;

typedef struct {
    const uint8_t *src;
    const uint8_t *src_end;
} c509_reader_t;

typedef struct {
    int numof;
    const c509_reader_t *reader;
} c509_array_iterator_t;

#define C509_WRITER_INITIALIZER(destination, end)   \
    (c509_writer_t){((uint8_t *)(destination)),     \
                    ((uint8_t *)(end))}

#define C509_READER_INITIALIZER(source, end)        \
    (c509_reader_t){((uint8_t *)(source)),          \
                    ((uint8_t *)(end))}

#define _C509_BUF_ALIGNED __attribute__((aligned(sizeof(uintptr_t))))

int c509_write_certificate_start(c509_writer_t *writer);

int c509_write_certificate_finish(c509_writer_t *writer);

typedef enum {
    C509_TYPE_CBOR = 0,
    C509_TYPE_DER = 1,
} c509_certificate_type_t;

int c509_write_type(c509_writer_t *writer,
                    c509_certificate_type_t type);

int c509_write_certificate_serial_number(c509_writer_t *writer,
                                         const uint8_t *serial,
                                         size_t serial_len);

int c509_write_name_start(c509_writer_t *writer);

int c509_write_name_finish(c509_writer_t *writer);

int c509_write_name_attribute_start(c509_writer_t *writer);

int c509_write_name_attribute_finish(c509_writer_t *writer);

typedef uint8_t c509_attribute_id_t;

typedef struct _C509_BUF_ALIGNED {
    c509_attribute_id_t id;
    bool printable_string;
    uint16_t value_len;
    const uint8_t *value;
} c509_name_attribute_t;

int c509_write_name_attribute(c509_writer_t *writer,
                              const c509_name_attribute_t *attr);

int c509_write_name_optimized(c509_writer_t *writer,
                              const uint8_t *common_name,
                              size_t len);

typedef struct {
    int64_t not_before;
    int64_t not_after;
} c509_validity_t;

int c509_write_validity(c509_writer_t *writer,
                        const c509_validity_t *validity);

typedef int8_t c509_pk_algorithm_id_t;

typedef struct {
    c509_pk_algorithm_id_t id;
    size_t len;
    const uint8_t *point;
} c509_ec_pk_info_t;

typedef struct {
    c509_pk_algorithm_id_t id;
    size_t mod_len;
    size_t exp_len;
    const uint8_t *modulus;
    const uint8_t *exponent;
} c509_rsa_pk_info_t;

typedef union {
    c509_pk_algorithm_id_t id;
    c509_rsa_pk_info_t rsa;
    c509_ec_pk_info_t ec;
} c509_pk_info_t;

int c509_write_rsa_subject_public_key_info(c509_writer_t *writer,
                                           const c509_rsa_pk_info_t *pk_info);

int c509_write_ec_subject_public_key_info(c509_writer_t *writer,
                                          const c509_ec_pk_info_t *pk_info);

typedef uint8_t c509_extension_id_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_id_t id;
    bool critical;
} c509_extension_base_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_base_t extension;
    size_t identifier_len;
    const uint8_t *identifier;
} c509_extension_subject_key_identifier_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_base_t extension;
    size_t identifier_len;
    const uint8_t *identifier;
#if 0
    size_t cert_issuer_len;
    const uint8_t *cert_issuer;
    size_t serial_len;
    const uint8_t *serial;
#endif
} c509_extension_authority_key_identifier_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_base_t extension;
    bool ca;
    int pathlen;
} c509_extension_basic_constraints_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_base_t extension;
    uint16_t usage;
} c509_extension_key_usage_t;

typedef struct {
    uint8_t addr[16];
    uint8_t len;
} c509_extension_ip_resource_prefix_t;

typedef struct {
    uint8_t min[16];
    uint8_t max[16];
} c509_extension_ip_resource_range_t;

typedef enum {
    C509_EXTENSION_IP_RESOURCE_NULL = 1,
    C509_EXTENSION_IP_RESOURCE_PREFIX = 2,
    C509_EXTENSION_IP_RESOURCE_RANGE = 3,
} c509_extension_ipv6_resource_type_t;

struct c509_extension_ipv6_range_or_prefix_list;
typedef struct c509_extension_ipv6_range_or_prefix_list {
    union {
        c509_extension_ip_resource_prefix_t prefix;
        c509_extension_ip_resource_range_t range;
    } res;
    unsigned char type;
    struct c509_extension_ipv6_range_or_prefix_list *next;
} c509_extension_ipv6_range_or_prefix_list_t;

typedef struct _C509_BUF_ALIGNED {
    c509_extension_base_t extension;
    c509_extension_ipv6_range_or_prefix_list_t range_or_prefix;
} c509_extension_ip_resource_t;

struct c509_extension_list;

typedef struct _C509_BUF_ALIGNED c509_extension_list {
    struct c509_extension_list *next;
    c509_extension_base_t extension;
} c509_extension_list_t;

int c509_write_extensions_start(c509_writer_t *writer);

int c509_write_extensions_finish(c509_writer_t *writer);

int c509_write_extension_subject_key_identifier(c509_writer_t *writer,
                                                const c509_extension_subject_key_identifier_t *ski);

int c509_write_extension_authority_key_identifier(c509_writer_t *writer,
                                                  const c509_extension_authority_key_identifier_t *aki);

int c509_write_extension_basic_constraints(c509_writer_t *writer,
                                           const c509_extension_basic_constraints_t *bc);

int c509_write_extension_key_usage(c509_writer_t *writer,
                                   const c509_extension_key_usage_t *ku);

int c509_write_extension_key_usage_optimized(c509_writer_t *writer,
                                             const c509_extension_key_usage_t *ku);

int c509_write_extension_ip_resource_start(c509_writer_t *writer,
                                           const c509_extension_ip_resource_t *ipr);

int c509_write_extension_ip_resource_finish(c509_writer_t *writer);

int c509_write_extension_ip_resource_null_finish(c509_writer_t *writer);

int c509_write_extension_ip_resource_address_or_range_start(c509_writer_t *writer);

int c509_write_extension_ip_resource_address_or_range_finish(c509_writer_t *writer);

int c509_write_extension_ip_resource_prefix(c509_writer_t *writer,
                                            const c509_extension_ip_resource_prefix_t *pfx);

int c509_write_extension_ip_resource_range(c509_writer_t *writer,
                                           const c509_extension_ip_resource_range_t *rg);

typedef int16_t c509_sig_algorithm_id_t;

typedef struct {
    c509_sig_algorithm_id_t id;
    size_t len;
    const uint8_t *value;
} c509_signature_rsa_t;

typedef struct {
    c509_sig_algorithm_id_t id;
    size_t r_len;
    size_t s_len;
    const uint8_t *r;
    const uint8_t *s;
} c509_signature_ecdsa_t;

typedef union {
    c509_sig_algorithm_id_t id;
    c509_signature_rsa_t rsa;
    c509_signature_ecdsa_t ecdsa;
} c509_signature_t;

int c509_write_signature_algorithm(c509_writer_t *writer,
                                   c509_sig_algorithm_id_t id);

int c509_write_signature_rsa(c509_writer_t *writer,
                             const c509_signature_rsa_t *sig);

int c509_write_signature_ecdsa(c509_writer_t *writer,
                            const c509_signature_ecdsa_t *sig);

int x509_to_c509(void *c509,
                 size_t c_size,
                 const void *x509,
                 size_t x_size);

int x509_to_c509_enc_version(void *c509,
                             size_t c_size,
                             const void *x509,
                             size_t x_size);

int x509_to_c509_enc_serial_number(void *c509,
                                   size_t c_size,
                                   const void *x509,
                                   size_t x_size);

int x509_to_c509_enc_signature(void *c509,
                               size_t c_size,
                               const void *x509,
                               size_t x_size);

int x509_to_c509_enc_issuer(void *c509,
                            size_t c_size,
                            const void *x509,
                            size_t x_size);

int x509_to_c509_enc_validity(void *c509,
                              size_t c_size,
                              const void *x509,
                              size_t x_size);

int x509_to_c509_enc_subject(void *c509,
                             size_t c_size,
                             const void *x509,
                             size_t x_size);

int x509_to_c509_enc_subject_public_key_info(void *c509,
                                             size_t c_size,
                                             const void *x509,
                                             size_t x_size);

int x509_to_c509_enc_issuer_unique_id(void *c509,
                                      size_t c_size,
                                      const void *x509,
                                      size_t x_size);

int x509_to_c509_enc_subject_unique_id(void *c509,
                                       size_t c_size,
                                       const void *x509,
                                       size_t x_size);

int x509_to_c509_enc_extensions(void *c509,
                                size_t c_size,
                                const void *x509,
                                size_t x_size);

int x509_to_c509_enc_signature_algorithm(void *c509,
                                         size_t c_size,
                                         const void *x509,
                                         size_t x_size,
                                         c509_sig_algorithm_id_t *sig_id);

int x509_to_c509_enc_signature_value(void *c509,
                                     size_t c_size,
                                     const void *x509,
                                     size_t x_size,
                                     c509_sig_algorithm_id_t sig_id);

int c509_read_certificate_start(c509_reader_t *reader,
                                c509_array_iterator_t *iter);

int c509_read_certificate_finish(c509_reader_t *reader,
                                 c509_array_iterator_t *iter);

int c509_read_version(c509_reader_t *reader,
                      int *version);

int c509_read_serial(c509_reader_t *reader,
                     const uint8_t **serial,
                     size_t *serial_len);

int c509_read_name_start(c509_reader_t *reader,
                         c509_array_iterator_t *iter);

int c509_read_name_finish(c509_reader_t *reader,
                          c509_array_iterator_t *iter);

int c509_read_name_next(c509_array_iterator_t *iter);

int c509_read_name_attribute_start(c509_reader_t *reader,
                                   c509_array_iterator_t *iter);

int c509_read_name_attribute_finish(c509_reader_t *reader,
                                    c509_array_iterator_t *iter);

int c509_read_name_attribute_next(c509_array_iterator_t *iter);


int c509_read_name_attribute(c509_reader_t *reader,
                             c509_name_attribute_t *attribute);

int c509_read_name(c509_reader_t *reader,
                   c509_name_attribute_t *name,
                   unsigned *max);

int c509_read_name_optimized(c509_reader_t *reader,
                             c509_name_attribute_t *name);

static inline int c509_read_issuer(c509_reader_t *reader,
                                   c509_name_attribute_t *name,
                                   unsigned *max) {
    return c509_read_name(reader, name, max);
}

static inline int c509_read_subject(c509_reader_t *reader,
                                    c509_name_attribute_t *name,
                                    unsigned *max) {
    return c509_read_name(reader, name, max);
}

int c509_read_validity(c509_reader_t *reader,
                       c509_validity_t *validity);

int c509_read_subject_public_key_info(c509_reader_t *reader,
                                      c509_pk_info_t *pki);

int c509_read_extensions_start(c509_reader_t *reader,
                               c509_array_iterator_t *iter);

int c509_read_extensions_finish(c509_reader_t *reader,
                                c509_array_iterator_t *iter);

int c509_extension_iterator_next(c509_array_iterator_t *iter);

int c509_read_extension(c509_reader_t *reader,
                        c509_extension_base_t *extension);

int c509_read_extension_subject_key_identifier(c509_reader_t *reader,
                                               c509_extension_subject_key_identifier_t *ski);

int c509_read_extension_key_usage(c509_reader_t *reader,
                                  c509_extension_key_usage_t *ku);

int c509_read_extension_key_usage_optimized(c509_reader_t *reader,
                                            c509_extension_key_usage_t *ku);

int c509_read_extension_authority_key_identifier(c509_reader_t *reader,
                                                 c509_extension_authority_key_identifier_t *aki);

int c509_read_extension_basic_constraints(c509_reader_t *reader,
                                          c509_extension_basic_constraints_t *bc);

int c509_read_extension_ip_resource_start(c509_reader_t *reader,
                                          c509_array_iterator_t *iter,
                                          c509_extension_ip_resource_t *ip);

int c509_read_extension_ip_resource_next(c509_array_iterator_t *iter);

int c509_read_extension_ip_resource_finish(c509_reader_t *reader,
                                           c509_array_iterator_t *iter);

int c509_read_extension_ip_resource_null(c509_reader_t *reader,
                                         c509_extension_ip_resource_t *ip);

int c509_read_extension_ip_resource_address_or_range_next(c509_array_iterator_t *iter);

int c509_read_extension_ip_resource_address_or_range_start(c509_reader_t *reader,
                                                           c509_array_iterator_t *iter);

int c509_read_extension_ip_resource_address_or_range_finish(c509_reader_t *reader,
                                                            c509_array_iterator_t *iter);

int c509_read_extension_ip_resource(c509_reader_t *reader,
                                    c509_extension_ipv6_range_or_prefix_list_t *range_or_prefix);

int c509_read_extensions(c509_reader_t *reader, void *extn_buf, size_t *extn_buf_size);

int c509_read_signature_algorithm(c509_reader_t *reader,
                                  c509_sig_algorithm_id_t *sig_id);

int c509_read_signature_rsa(c509_reader_t *reader,
                            c509_signature_rsa_t *signature);

int c509_read_signature_ecdsa(c509_reader_t *reader,
                              c509_signature_ecdsa_t *signature);

int c509_read_signature(c509_reader_t *reader,
                        c509_signature_t *signature);

int c509_to_x509(void *x509,
                 size_t x_size,
                 const void *c509,
                 size_t c_size);

int c509_to_x509_enc_version(void *x509,
                             size_t x_size,
                             const void *c509,
                             size_t c_size);

int c509_to_x509_enc_serial(void *x509,
                            size_t x_size,
                            const void *c509,
                            size_t c_size);

int c509_to_x509_enc_issuer(void *x509,
                            size_t x_size,
                            const void *c509,
                            size_t c_size);

int c509_to_x509_enc_validity(void *x509,
                              size_t x_size,
                              const void *c509,
                              size_t c_size);

int c509_to_x509_enc_subject(void *x509,
                             size_t x_size,
                             const void *c509,
                             size_t c_size);

int c509_to_x509_enc_subject_public_key_info(void *x509,
                                             size_t x_size,
                                             const void *c509,
                                             size_t c_size);

int c509_to_x509_enc_extennsions(void *x509,
                                 size_t x_size,
                                 const void *c509,
                                 size_t c_size);

int c509_to_x509_enc_signature_algorithm(void *x509,
                                         size_t x_size,
                                         const void *c509,
                                         size_t c_size,
                                         c509_sig_algorithm_id_t *id);

int c509_to_x509_enc_signature_value(void *x509,
                                     size_t x_size,
                                     const void *c509,
                                     size_t c_size,
                                     c509_sig_algorithm_id_t id);
typedef struct {
    void *buf;
    size_t buf_size;
    int type;
    const uint8_t *serial;
    uint8_t serial_len;
    c509_name_attribute_t *issuer;
    c509_validity_t validity;
    c509_name_attribute_t *subject;
    c509_pk_info_t subject_public_key;
    c509_extension_list_t *extensions;
    c509_signature_t signature;
} c509_crt_t;

void c509_init_certificate(c509_crt_t *c509, void *buf, size_t size);

int c509_parse_certificate(c509_crt_t *c509, const void *buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif
