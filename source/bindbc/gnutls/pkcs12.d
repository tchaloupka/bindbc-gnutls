module bindbc.gnutls.pkcs12;

import bindbc.gnutls.gnutls;

struct gnutls_pkcs12_int;
alias gnutls_pkcs12_t = gnutls_pkcs12_int*;

struct gnutls_pkcs12_bag_int;
alias gnutls_pkcs12_bag_t = gnutls_pkcs12_bag_int*;

enum GNUTLS_PKCS12_SP_INCLUDE_SELF_SIGNED = 1;
enum gnutls_pkcs12_bag_type_t
{
    GNUTLS_BAG_EMPTY = 0,
    GNUTLS_BAG_PKCS8_ENCRYPTED_KEY = 1,
    GNUTLS_BAG_PKCS8_KEY = 2,
    GNUTLS_BAG_CERTIFICATE = 3,
    GNUTLS_BAG_CRL = 4,
    GNUTLS_BAG_SECRET = 5,

    GNUTLS_BAG_ENCRYPTED = 10,
    GNUTLS_BAG_UNKNOWN = 20
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_pkcs12_init (gnutls_pkcs12_t* pkcs12);
    void gnutls_pkcs12_deinit (gnutls_pkcs12_t pkcs12);
    int gnutls_pkcs12_import (gnutls_pkcs12_t pkcs12, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_pkcs12_export (gnutls_pkcs12_t pkcs12, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_pkcs12_export2 (gnutls_pkcs12_t pkcs12, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_pkcs12_get_bag (gnutls_pkcs12_t pkcs12, int indx, gnutls_pkcs12_bag_t bag);
    int gnutls_pkcs12_set_bag (gnutls_pkcs12_t pkcs12, gnutls_pkcs12_bag_t bag);
    int gnutls_pkcs12_generate_mac (gnutls_pkcs12_t pkcs12, const(char)* pass);
    int gnutls_pkcs12_generate_mac2 (gnutls_pkcs12_t pkcs12, gnutls_mac_algorithm_t mac, const(char)* pass);
    int gnutls_pkcs12_verify_mac (gnutls_pkcs12_t pkcs12, const(char)* pass);
    int gnutls_pkcs12_bag_decrypt (gnutls_pkcs12_bag_t bag, const(char)* pass);
    int gnutls_pkcs12_bag_encrypt (gnutls_pkcs12_bag_t bag, const(char)* pass, uint flags);
    int gnutls_pkcs12_bag_enc_info (gnutls_pkcs12_bag_t bag, uint* schema, uint* cipher, void* salt, uint* salt_size, uint* iter_count, char** oid);
    int gnutls_pkcs12_mac_info (gnutls_pkcs12_t pkcs12, uint* mac, void* salt, uint* salt_size, uint* iter_count, char** oid);
    int gnutls_pkcs12_simple_parse (gnutls_pkcs12_t p12, const(char)* password, gnutls_x509_privkey_t* key, gnutls_x509_crt_t** chain, uint* chain_len, gnutls_x509_crt_t** extra_certs, uint* extra_certs_len, gnutls_x509_crl_t* crl, uint flags);
    int gnutls_pkcs12_bag_get_type (gnutls_pkcs12_bag_t bag, uint indx);
    int gnutls_pkcs12_bag_get_data (gnutls_pkcs12_bag_t bag, uint indx, gnutls_datum_t* data);
    int gnutls_pkcs12_bag_set_data (gnutls_pkcs12_bag_t bag, gnutls_pkcs12_bag_type_t type, const(gnutls_datum_t)* data);
    int gnutls_pkcs12_bag_set_crl (gnutls_pkcs12_bag_t bag, gnutls_x509_crl_t crl);
    int gnutls_pkcs12_bag_set_crt (gnutls_pkcs12_bag_t bag, gnutls_x509_crt_t crt);
    int gnutls_pkcs12_bag_set_privkey (gnutls_pkcs12_bag_t bag, gnutls_x509_privkey_t privkey, const(char)* password, uint flags);
    int gnutls_pkcs12_bag_init (gnutls_pkcs12_bag_t* bag);
    void gnutls_pkcs12_bag_deinit (gnutls_pkcs12_bag_t bag);
    int gnutls_pkcs12_bag_get_count (gnutls_pkcs12_bag_t bag);
    int gnutls_pkcs12_bag_get_key_id (gnutls_pkcs12_bag_t bag, uint indx, gnutls_datum_t* id);
    int gnutls_pkcs12_bag_set_key_id (gnutls_pkcs12_bag_t bag, uint indx, const(gnutls_datum_t)* id);
    int gnutls_pkcs12_bag_get_friendly_name (gnutls_pkcs12_bag_t bag, uint indx, char** name);
    int gnutls_pkcs12_bag_set_friendly_name (gnutls_pkcs12_bag_t bag, uint indx, const(char)* name);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_pkcs12_init = int function (gnutls_pkcs12_t* pkcs12);
        alias pgnutls_pkcs12_deinit = void function (gnutls_pkcs12_t pkcs12);
        alias pgnutls_pkcs12_import = int function (gnutls_pkcs12_t pkcs12, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_pkcs12_export = int function (gnutls_pkcs12_t pkcs12, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_pkcs12_export2 = int function (gnutls_pkcs12_t pkcs12, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_pkcs12_get_bag = int function (gnutls_pkcs12_t pkcs12, int indx, gnutls_pkcs12_bag_t bag);
        alias pgnutls_pkcs12_set_bag = int function (gnutls_pkcs12_t pkcs12, gnutls_pkcs12_bag_t bag);
        alias pgnutls_pkcs12_generate_mac = int function (gnutls_pkcs12_t pkcs12, const(char)* pass);
        alias pgnutls_pkcs12_generate_mac2 = int function (gnutls_pkcs12_t pkcs12, gnutls_mac_algorithm_t mac, const(char)* pass);
        alias pgnutls_pkcs12_verify_mac = int function (gnutls_pkcs12_t pkcs12, const(char)* pass);
        alias pgnutls_pkcs12_bag_decrypt = int function (gnutls_pkcs12_bag_t bag, const(char)* pass);
        alias pgnutls_pkcs12_bag_encrypt = int function (gnutls_pkcs12_bag_t bag, const(char)* pass, uint flags);
        alias pgnutls_pkcs12_bag_enc_info = int function (gnutls_pkcs12_bag_t bag, uint* schema, uint* cipher, void* salt, uint* salt_size, uint* iter_count, char** oid);
        alias pgnutls_pkcs12_mac_info = int function (gnutls_pkcs12_t pkcs12, uint* mac, void* salt, uint* salt_size, uint* iter_count, char** oid);
        alias pgnutls_pkcs12_simple_parse = int function (gnutls_pkcs12_t p12, const(char)* password, gnutls_x509_privkey_t* key, gnutls_x509_crt_t** chain, uint* chain_len, gnutls_x509_crt_t** extra_certs, uint* extra_certs_len, gnutls_x509_crl_t* crl, uint flags);
        alias pgnutls_pkcs12_bag_get_type = int function (gnutls_pkcs12_bag_t bag, uint indx);
        alias pgnutls_pkcs12_bag_get_data = int function (gnutls_pkcs12_bag_t bag, uint indx, gnutls_datum_t* data);
        alias pgnutls_pkcs12_bag_set_data = int function (gnutls_pkcs12_bag_t bag, gnutls_pkcs12_bag_type_t type, const(gnutls_datum_t)* data);
        alias pgnutls_pkcs12_bag_set_crl = int function (gnutls_pkcs12_bag_t bag, gnutls_x509_crl_t crl);
        alias pgnutls_pkcs12_bag_set_crt = int function (gnutls_pkcs12_bag_t bag, gnutls_x509_crt_t crt);
        alias pgnutls_pkcs12_bag_set_privkey = int function (gnutls_pkcs12_bag_t bag, gnutls_x509_privkey_t privkey, const(char)* password, uint flags);
        alias pgnutls_pkcs12_bag_init = int function (gnutls_pkcs12_bag_t* bag);
        alias pgnutls_pkcs12_bag_deinit = void function (gnutls_pkcs12_bag_t bag);
        alias pgnutls_pkcs12_bag_get_count = int function (gnutls_pkcs12_bag_t bag);
        alias pgnutls_pkcs12_bag_get_key_id = int function (gnutls_pkcs12_bag_t bag, uint indx, gnutls_datum_t* id);
        alias pgnutls_pkcs12_bag_set_key_id = int function (gnutls_pkcs12_bag_t bag, uint indx, const(gnutls_datum_t)* id);
        alias pgnutls_pkcs12_bag_get_friendly_name = int function (gnutls_pkcs12_bag_t bag, uint indx, char** name);
        alias pgnutls_pkcs12_bag_set_friendly_name = int function (gnutls_pkcs12_bag_t bag, uint indx, const(char)* name);
    }

    __gshared
    {
        pgnutls_pkcs12_init gnutls_pkcs12_init;
        pgnutls_pkcs12_deinit gnutls_pkcs12_deinit;
        pgnutls_pkcs12_import gnutls_pkcs12_import;
        pgnutls_pkcs12_export gnutls_pkcs12_export;
        pgnutls_pkcs12_export2 gnutls_pkcs12_export2;
        pgnutls_pkcs12_get_bag gnutls_pkcs12_get_bag;
        pgnutls_pkcs12_set_bag gnutls_pkcs12_set_bag;
        pgnutls_pkcs12_generate_mac gnutls_pkcs12_generate_mac;
        pgnutls_pkcs12_generate_mac2 gnutls_pkcs12_generate_mac2;
        pgnutls_pkcs12_verify_mac gnutls_pkcs12_verify_mac;
        pgnutls_pkcs12_bag_decrypt gnutls_pkcs12_bag_decrypt;
        pgnutls_pkcs12_bag_encrypt gnutls_pkcs12_bag_encrypt;
        pgnutls_pkcs12_bag_enc_info gnutls_pkcs12_bag_enc_info;
        pgnutls_pkcs12_mac_info gnutls_pkcs12_mac_info;
        pgnutls_pkcs12_simple_parse gnutls_pkcs12_simple_parse;
        pgnutls_pkcs12_bag_get_type gnutls_pkcs12_bag_get_type;
        pgnutls_pkcs12_bag_get_data gnutls_pkcs12_bag_get_data;
        pgnutls_pkcs12_bag_set_data gnutls_pkcs12_bag_set_data;
        pgnutls_pkcs12_bag_set_crl gnutls_pkcs12_bag_set_crl;
        pgnutls_pkcs12_bag_set_crt gnutls_pkcs12_bag_set_crt;
        pgnutls_pkcs12_bag_set_privkey gnutls_pkcs12_bag_set_privkey;
        pgnutls_pkcs12_bag_init gnutls_pkcs12_bag_init;
        pgnutls_pkcs12_bag_deinit gnutls_pkcs12_bag_deinit;
        pgnutls_pkcs12_bag_get_count gnutls_pkcs12_bag_get_count;
        pgnutls_pkcs12_bag_get_key_id gnutls_pkcs12_bag_get_key_id;
        pgnutls_pkcs12_bag_set_key_id gnutls_pkcs12_bag_set_key_id;
        pgnutls_pkcs12_bag_get_friendly_name gnutls_pkcs12_bag_get_friendly_name;
        pgnutls_pkcs12_bag_set_friendly_name gnutls_pkcs12_bag_set_friendly_name;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindPkcs12(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_pkcs12_init, "gnutls_pkcs12_init");
        lib.bindSymbol_stdcall(gnutls_pkcs12_deinit, "gnutls_pkcs12_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs12_import, "gnutls_pkcs12_import");
        lib.bindSymbol_stdcall(gnutls_pkcs12_export, "gnutls_pkcs12_export");
        lib.bindSymbol_stdcall(gnutls_pkcs12_export2, "gnutls_pkcs12_export2");
        lib.bindSymbol_stdcall(gnutls_pkcs12_get_bag, "gnutls_pkcs12_get_bag");
        lib.bindSymbol_stdcall(gnutls_pkcs12_set_bag, "gnutls_pkcs12_set_bag");
        lib.bindSymbol_stdcall(gnutls_pkcs12_generate_mac, "gnutls_pkcs12_generate_mac");
        lib.bindSymbol_stdcall(gnutls_pkcs12_generate_mac2, "gnutls_pkcs12_generate_mac2");
        lib.bindSymbol_stdcall(gnutls_pkcs12_verify_mac, "gnutls_pkcs12_verify_mac");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_decrypt, "gnutls_pkcs12_bag_decrypt");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_encrypt, "gnutls_pkcs12_bag_encrypt");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_enc_info, "gnutls_pkcs12_bag_enc_info");
        lib.bindSymbol_stdcall(gnutls_pkcs12_mac_info, "gnutls_pkcs12_mac_info");
        lib.bindSymbol_stdcall(gnutls_pkcs12_simple_parse, "gnutls_pkcs12_simple_parse");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_get_type, "gnutls_pkcs12_bag_get_type");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_get_data, "gnutls_pkcs12_bag_get_data");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_data, "gnutls_pkcs12_bag_set_data");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_crl, "gnutls_pkcs12_bag_set_crl");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_crt, "gnutls_pkcs12_bag_set_crt");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_privkey, "gnutls_pkcs12_bag_set_privkey");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_init, "gnutls_pkcs12_bag_init");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_deinit, "gnutls_pkcs12_bag_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_get_count, "gnutls_pkcs12_bag_get_count");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_get_key_id, "gnutls_pkcs12_bag_get_key_id");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_key_id, "gnutls_pkcs12_bag_set_key_id");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_get_friendly_name, "gnutls_pkcs12_bag_get_friendly_name");
        lib.bindSymbol_stdcall(gnutls_pkcs12_bag_set_friendly_name, "gnutls_pkcs12_bag_set_friendly_name");
    }
}
