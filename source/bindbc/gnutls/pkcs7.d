module bindbc.gnutls.pkcs7;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import core.sys.posix.sys.select;

struct gnutls_pkcs7_int;
alias gnutls_pkcs7_t = gnutls_pkcs7_int*;

enum GNUTLS_PKCS7_EDATA_GET_RAW = 1 << 24;

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

enum GNUTLS_PKCS7_ATTR_ENCODE_OCTET_STRING = 1;

enum gnutls_pkcs7_sign_flags
{
    GNUTLS_PKCS7_EMBED_DATA = 1,
    GNUTLS_PKCS7_INCLUDE_TIME = 1 << 1,
    GNUTLS_PKCS7_INCLUDE_CERT = 1 << 2,
    GNUTLS_PKCS7_WRITE_SPKI = 1 << 3
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_pkcs7_init (gnutls_pkcs7_t* pkcs7);
    void gnutls_pkcs7_deinit (gnutls_pkcs7_t pkcs7);
    int gnutls_pkcs7_import (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_pkcs7_export (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_pkcs7_export2 (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_pkcs7_get_signature_count (gnutls_pkcs7_t pkcs7);
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
    void gnutls_pkcs7_signature_info_deinit (gnutls_pkcs7_signature_info_st* info);
    int gnutls_pkcs7_get_signature_info (gnutls_pkcs7_t pkcs7, uint idx, gnutls_pkcs7_signature_info_st* info);
    int gnutls_pkcs7_verify_direct (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, uint idx, const(gnutls_datum_t)* data, uint flags);
    int gnutls_pkcs7_verify (gnutls_pkcs7_t pkcs7, gnutls_x509_trust_list_t tl, gnutls_typed_vdata_st* vdata, uint vdata_size, uint idx, const(gnutls_datum_t)* data, uint flags);
    int gnutls_pkcs7_add_attr (gnutls_pkcs7_attrs_t* list, const(char)* oid, gnutls_datum_t* data, uint flags);
    void gnutls_pkcs7_attrs_deinit (gnutls_pkcs7_attrs_t list);
    int gnutls_pkcs7_get_attr (gnutls_pkcs7_attrs_t list, uint idx, char** oid, gnutls_datum_t* data, uint flags);
    int gnutls_pkcs7_sign (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, gnutls_privkey_t signer_key, const(gnutls_datum_t)* data, gnutls_pkcs7_attrs_t signed_attrs, gnutls_pkcs7_attrs_t unsigned_attrs, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_pkcs7_get_crt_raw2 (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* cert);
    int gnutls_pkcs7_get_crl_raw2 (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* crl);
    int gnutls_pkcs7_print (gnutls_pkcs7_t pkcs7, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    int gnutls_pkcs7_print_signature_info (gnutls_pkcs7_signature_info_st* info, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_pkcs7_init = int function (gnutls_pkcs7_t* pkcs7);
        alias pgnutls_pkcs7_deinit = void function (gnutls_pkcs7_t pkcs7);
        alias pgnutls_pkcs7_import = int function (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_pkcs7_export = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_pkcs7_export2 = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_pkcs7_get_signature_count = int function (gnutls_pkcs7_t pkcs7);
        alias pgnutls_pkcs7_get_embedded_data = int function (gnutls_pkcs7_t pkcs7, uint flags, gnutls_datum_t* data);
        alias pgnutls_pkcs7_get_embedded_data_oid = const(char)* function (gnutls_pkcs7_t pkcs7);
        alias pgnutls_pkcs7_get_crt_count = int function (gnutls_pkcs7_t pkcs7);
        alias pgnutls_pkcs7_get_crt_raw = int function (gnutls_pkcs7_t pkcs7, uint indx, void* certificate, size_t* certificate_size);
        alias pgnutls_pkcs7_set_crt_raw = int function (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* crt);
        alias pgnutls_pkcs7_set_crt = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t crt);
        alias pgnutls_pkcs7_delete_crt = int function (gnutls_pkcs7_t pkcs7, int indx);
        alias pgnutls_pkcs7_get_crl_raw = int function (gnutls_pkcs7_t pkcs7, uint indx, void* crl, size_t* crl_size);
        alias pgnutls_pkcs7_get_crl_count = int function (gnutls_pkcs7_t pkcs7);
        alias pgnutls_pkcs7_set_crl_raw = int function (gnutls_pkcs7_t pkcs7, const(gnutls_datum_t)* crl);
        alias pgnutls_pkcs7_set_crl = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crl_t crl);
        alias pgnutls_pkcs7_delete_crl = int function (gnutls_pkcs7_t pkcs7, int indx);
        alias pgnutls_pkcs7_signature_info_deinit = void function (gnutls_pkcs7_signature_info_st* info);
        alias pgnutls_pkcs7_get_signature_info = int function (gnutls_pkcs7_t pkcs7, uint idx, gnutls_pkcs7_signature_info_st* info);
        alias pgnutls_pkcs7_verify_direct = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, uint idx, const(gnutls_datum_t)* data, uint flags);
        alias pgnutls_pkcs7_verify = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_trust_list_t tl, gnutls_typed_vdata_st* vdata, uint vdata_size, uint idx, const(gnutls_datum_t)* data, uint flags);
        alias pgnutls_pkcs7_add_attr = int function (gnutls_pkcs7_attrs_t* list, const(char)* oid, gnutls_datum_t* data, uint flags);
        alias pgnutls_pkcs7_attrs_deinit = void function (gnutls_pkcs7_attrs_t list);
        alias pgnutls_pkcs7_get_attr = int function (gnutls_pkcs7_attrs_t list, uint idx, char** oid, gnutls_datum_t* data, uint flags);
        alias pgnutls_pkcs7_sign = int function (gnutls_pkcs7_t pkcs7, gnutls_x509_crt_t signer, gnutls_privkey_t signer_key, const(gnutls_datum_t)* data, gnutls_pkcs7_attrs_t signed_attrs, gnutls_pkcs7_attrs_t unsigned_attrs, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_pkcs7_get_crt_raw2 = int function (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* cert);
        alias pgnutls_pkcs7_get_crl_raw2 = int function (gnutls_pkcs7_t pkcs7, uint indx, gnutls_datum_t* crl);
        alias pgnutls_pkcs7_print = int function (gnutls_pkcs7_t pkcs7, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
        alias pgnutls_pkcs7_print_signature_info = int function (gnutls_pkcs7_signature_info_st* info, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    }

    __gshared
    {
        pgnutls_pkcs7_init gnutls_pkcs7_init;
        pgnutls_pkcs7_deinit gnutls_pkcs7_deinit;
        pgnutls_pkcs7_import gnutls_pkcs7_import;
        pgnutls_pkcs7_export gnutls_pkcs7_export;
        pgnutls_pkcs7_export2 gnutls_pkcs7_export2;
        pgnutls_pkcs7_get_signature_count gnutls_pkcs7_get_signature_count;
        pgnutls_pkcs7_get_embedded_data gnutls_pkcs7_get_embedded_data;
        pgnutls_pkcs7_get_embedded_data_oid gnutls_pkcs7_get_embedded_data_oid;
        pgnutls_pkcs7_get_crt_count gnutls_pkcs7_get_crt_count;
        pgnutls_pkcs7_get_crt_raw gnutls_pkcs7_get_crt_raw;
        pgnutls_pkcs7_set_crt_raw gnutls_pkcs7_set_crt_raw;
        pgnutls_pkcs7_set_crt gnutls_pkcs7_set_crt;
        pgnutls_pkcs7_delete_crt gnutls_pkcs7_delete_crt;
        pgnutls_pkcs7_get_crl_raw gnutls_pkcs7_get_crl_raw;
        pgnutls_pkcs7_get_crl_count gnutls_pkcs7_get_crl_count;
        pgnutls_pkcs7_set_crl_raw gnutls_pkcs7_set_crl_raw;
        pgnutls_pkcs7_set_crl gnutls_pkcs7_set_crl;
        pgnutls_pkcs7_delete_crl gnutls_pkcs7_delete_crl;
        pgnutls_pkcs7_signature_info_deinit gnutls_pkcs7_signature_info_deinit;
        pgnutls_pkcs7_get_signature_info gnutls_pkcs7_get_signature_info;
        pgnutls_pkcs7_verify_direct gnutls_pkcs7_verify_direct;
        pgnutls_pkcs7_verify gnutls_pkcs7_verify;
        pgnutls_pkcs7_add_attr gnutls_pkcs7_add_attr;
        pgnutls_pkcs7_attrs_deinit gnutls_pkcs7_attrs_deinit;
        pgnutls_pkcs7_get_attr gnutls_pkcs7_get_attr;
        pgnutls_pkcs7_sign gnutls_pkcs7_sign;
        pgnutls_pkcs7_get_crt_raw2 gnutls_pkcs7_get_crt_raw2;
        pgnutls_pkcs7_get_crl_raw2 gnutls_pkcs7_get_crl_raw2;
        pgnutls_pkcs7_print gnutls_pkcs7_print;
        pgnutls_pkcs7_print_signature_info gnutls_pkcs7_print_signature_info;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindPkcs7(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_pkcs7_init, "gnutls_pkcs7_init");
        lib.bindSymbol_stdcall(gnutls_pkcs7_deinit, "gnutls_pkcs7_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs7_import, "gnutls_pkcs7_import");
        lib.bindSymbol_stdcall(gnutls_pkcs7_export, "gnutls_pkcs7_export");
        lib.bindSymbol_stdcall(gnutls_pkcs7_export2, "gnutls_pkcs7_export2");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_signature_count, "gnutls_pkcs7_get_signature_count");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_embedded_data, "gnutls_pkcs7_get_embedded_data");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_embedded_data_oid, "gnutls_pkcs7_get_embedded_data_oid");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crt_count, "gnutls_pkcs7_get_crt_count");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crt_raw, "gnutls_pkcs7_get_crt_raw");
        lib.bindSymbol_stdcall(gnutls_pkcs7_set_crt_raw, "gnutls_pkcs7_set_crt_raw");
        lib.bindSymbol_stdcall(gnutls_pkcs7_set_crt, "gnutls_pkcs7_set_crt");
        lib.bindSymbol_stdcall(gnutls_pkcs7_delete_crt, "gnutls_pkcs7_delete_crt");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crl_raw, "gnutls_pkcs7_get_crl_raw");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crl_count, "gnutls_pkcs7_get_crl_count");
        lib.bindSymbol_stdcall(gnutls_pkcs7_set_crl_raw, "gnutls_pkcs7_set_crl_raw");
        lib.bindSymbol_stdcall(gnutls_pkcs7_set_crl, "gnutls_pkcs7_set_crl");
        lib.bindSymbol_stdcall(gnutls_pkcs7_delete_crl, "gnutls_pkcs7_delete_crl");
        lib.bindSymbol_stdcall(gnutls_pkcs7_signature_info_deinit, "gnutls_pkcs7_signature_info_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_signature_info, "gnutls_pkcs7_get_signature_info");
        lib.bindSymbol_stdcall(gnutls_pkcs7_verify_direct, "gnutls_pkcs7_verify_direct");
        lib.bindSymbol_stdcall(gnutls_pkcs7_verify, "gnutls_pkcs7_verify");
        lib.bindSymbol_stdcall(gnutls_pkcs7_add_attr, "gnutls_pkcs7_add_attr");
        lib.bindSymbol_stdcall(gnutls_pkcs7_attrs_deinit, "gnutls_pkcs7_attrs_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_attr, "gnutls_pkcs7_get_attr");
        lib.bindSymbol_stdcall(gnutls_pkcs7_sign, "gnutls_pkcs7_sign");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crt_raw2, "gnutls_pkcs7_get_crt_raw2");
        lib.bindSymbol_stdcall(gnutls_pkcs7_get_crl_raw2, "gnutls_pkcs7_get_crl_raw2");
        lib.bindSymbol_stdcall(gnutls_pkcs7_print, "gnutls_pkcs7_print");
        lib.bindSymbol_stdcall(gnutls_pkcs7_print_signature_info, "gnutls_pkcs7_print_signature_info");
    }
}
