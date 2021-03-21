module bindbc.gnutls.pkcs7;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import core.sys.posix.sys.select;

extern (C):

struct gnutls_pkcs7_int;
alias gnutls_pkcs7_t = gnutls_pkcs7_int*;

int gnutls_pkcs7_init (gnutls_pkcs7_t* pkcs7);
void gnutls_pkcs7_deinit (gnutls_pkcs7_t pkcs7);
int gnutls_pkcs7_import (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
int gnutls_pkcs7_export (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
int gnutls_pkcs7_export2 (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);

int gnutls_pkcs7_get_signature_count (gnutls_pkcs7_t pkcs7);

enum GNUTLS_PKCS7_EDATA_GET_RAW = 1 << 24;
int gnutls_pkcs7_get_embedded_data (gnutls_pkcs7_t pkcs7, uint flags, gnutls_datum_t* data);

const(char)* gnutls_pkcs7_get_embedded_data_oid (gnutls_pkcs7_t pkcs7);

int gnutls_pkcs7_get_crt_count (gnutls_pkcs7_t pkcs7);
int gnutls_pkcs7_get_crt_raw (gnutls_pkcs7_t pkcs7, uint indx, void* certificate, size_t* certificate_size);

int gnutls_pkcs7_set_crt_raw (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* crt);
int gnutls_pkcs7_set_crt (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t crt);
int gnutls_pkcs7_delete_crt (gnutls_pkcs7_t pkcs7, int indx);

int gnutls_pkcs7_get_crl_raw (gnutls_pkcs7_t pkcs7, uint indx, void* crl, size_t* crl_size);
int gnutls_pkcs7_get_crl_count (gnutls_pkcs7_t pkcs7);

int gnutls_pkcs7_set_crl_raw (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* crl);
int gnutls_pkcs7_set_crl (gnutls_pkcs7_t pkcs7, gnutls_x509_crl_t crl);
int gnutls_pkcs7_delete_crl (gnutls_pkcs7_t pkcs7, int indx);

struct gnutls_pkcs7_attrs_st;
alias gnutls_pkcs7_attrs_t = gnutls_pkcs7_attrs_st*;

struct gnutls_pkcs7_signature_info_st
{
    gnutls_sign_algorithm_t algo;
    gnutls_datum_t sig;
    gnutls_datum_t issuer_dn;
    gnutls_datum_t signer_serial;
    gnutls_datum_t issuer_keyid;
    time_t signing_time;
    gnutls_pkcs7_attrs_t signed_attrs;
    gnutls_pkcs7_attrs_t unsigned_attrs;
    char[64] pad;
}

void gnutls_pkcs7_signature_info_deinit (gnutls_pkcs7_signature_info_st* info);
int gnutls_pkcs7_get_signature_info (gnutls_pkcs7_t pkcs7, uint idx, gnutls_pkcs7_signature_info_st* info);

int gnutls_pkcs7_verify_direct (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, uint idx, const(gnutls_datum_t)* data, uint flags);
int gnutls_pkcs7_verify (gnutls_pkcs7_t pkcs7, gnutls_x509_trust_list_t tl, gnutls_typed_vdata_st* vdata, uint vdata_size, uint idx, const(gnutls_datum_t)* data, uint flags);

enum GNUTLS_PKCS7_ATTR_ENCODE_OCTET_STRING = 1;
int gnutls_pkcs7_add_attr (gnutls_pkcs7_attrs_t* list, const(char)* oid, gnutls_datum_t* data, uint flags);
void gnutls_pkcs7_attrs_deinit (gnutls_pkcs7_attrs_t list);
int gnutls_pkcs7_get_attr (gnutls_pkcs7_attrs_t list, uint idx, char** oid, gnutls_datum_t* data, uint flags);

enum gnutls_pkcs7_sign_flags
{
    GNUTLS_PKCS7_EMBED_DATA = 1,
    GNUTLS_PKCS7_INCLUDE_TIME = 1 << 1,
    GNUTLS_PKCS7_INCLUDE_CERT = 1 << 2,
    GNUTLS_PKCS7_WRITE_SPKI = 1 << 3
}

int gnutls_pkcs7_sign (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, gnutls_privkey_t signer_key, const(gnutls_datum_t)* data, gnutls_pkcs7_attrs_t signed_attrs, gnutls_pkcs7_attrs_t unsigned_attrs, gnutls_digest_algorithm_t dig, uint flags);

int gnutls_pkcs7_get_crt_raw2 (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* cert);
int gnutls_pkcs7_get_crl_raw2 (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* crl);

int gnutls_pkcs7_print (gnutls_pkcs7_t pkcs7, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);

int gnutls_pkcs7_print_signature_info (gnutls_pkcs7_signature_info_st* info, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
