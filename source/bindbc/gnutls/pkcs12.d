module bindbc.gnutls.pkcs12;

import bindbc.gnutls.gnutls;

extern (C):

struct gnutls_pkcs12_int;
alias gnutls_pkcs12_t = gnutls_pkcs12_int*;

struct gnutls_pkcs12_bag_int;
alias gnutls_pkcs12_bag_t = gnutls_pkcs12_bag_int*;

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

enum GNUTLS_PKCS12_SP_INCLUDE_SELF_SIGNED = 1;
int gnutls_pkcs12_simple_parse (gnutls_pkcs12_t p12, const(char)* password, gnutls_x509_privkey_t* key, gnutls_x509_crt_t** chain, uint* chain_len, gnutls_x509_crt_t** extra_certs, uint* extra_certs_len, gnutls_x509_crl_t* crl, uint flags);

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
