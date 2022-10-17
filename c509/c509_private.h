#ifndef PRIVATE_C509_H
#define PRIVATE_C509_H

#include "include/c509.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct __attribute__((packed)) {
    c509_attribute_id_t id;
    unsigned char len;
/*  unsigned char oid[]; */
} c509_attribute_t;

const c509_attribute_t *c509_attribute_iterator(const c509_attribute_t *last);
const c509_attribute_t *c509_attribute_get_by_id(c509_attribute_id_t id);
const void *c509_attribute_get_oid(const c509_attribute_t *attr);

typedef struct __attribute__((packed)) {
    unsigned char len;
/*  unsigned char oid[]; */
} c509_algorithm_parameters_t;

const void *c509_algorithm_parameters_get_oid(const c509_algorithm_parameters_t *par);
bool c509_algorithm_parameters_is_null(const c509_algorithm_parameters_t *par);

typedef struct __attribute__((packed)) {
    const c509_algorithm_parameters_t *params;
    c509_pk_algorithm_id_t id;
    unsigned char len;
/*  unsigned char oid[]; */
} c509_pk_algorithm_t;

const c509_pk_algorithm_t *c509_pk_algorithm_iterator(const c509_pk_algorithm_t *last);
const c509_pk_algorithm_t *c509_pk_algorithm_get_by_id(c509_pk_algorithm_id_t id);
const void *c509_pk_algorithm_get_oid(const c509_pk_algorithm_t *alg);

bool c509_pk_is_rsa(c509_pk_algorithm_id_t id);
bool c509_pk_is_ec(c509_pk_algorithm_id_t id);

typedef struct __attribute__((packed)) {
    c509_extension_id_t id;
    unsigned char len;
/*  unsigned char oid[]; */
} c509_extension_t;

const c509_extension_t *c509_extension_iterator(const c509_extension_t *last);
const c509_extension_t *c509_extension_get_by_id(c509_extension_id_t id);
const void *c509_extension_get_oid(const c509_extension_t *extn);

typedef struct __attribute__((packed)) {
    const c509_algorithm_parameters_t *params;
    c509_sig_algorithm_id_t id;
    unsigned char len;
/*  unsigned char oid[]; */
} c509_sig_algorithm_t;

const c509_sig_algorithm_t *c509_sig_algorithm_iterator(const c509_sig_algorithm_t *last);
const c509_sig_algorithm_t *c509_sig_algorithm_get_by_id(c509_sig_algorithm_id_t id);
const void *c509_sig_algorithm_get_oid(const c509_sig_algorithm_t *sig);

bool c509_sig_is_rsa(c509_sig_algorithm_id_t id);
bool c509_sig_is_ec(c509_sig_algorithm_id_t id);

#ifdef __cplusplus
}
#endif

#endif
