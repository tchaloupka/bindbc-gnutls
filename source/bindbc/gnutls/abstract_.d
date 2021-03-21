module bindbc.gnutls.abstract_;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.openpgp;
import bindbc.gnutls.pkcs11;
import bindbc.gnutls.tpm;
import bindbc.gnutls.x509;

extern (C):

enum GNUTLS_PUBKEY_VERIFY_FLAG_TLS_RSA = GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA;

enum gnutls_pubkey_flags
{
    GNUTLS_PUBKEY_DISABLE_CALLBACKS = 1 << 2,
    GNUTLS_PUBKEY_GET_OPENPGP_FINGERPRINT = 1 << 3
}

alias gnutls_pubkey_flags_t = gnutls_pubkey_flags;

enum gnutls_abstract_export_flags
{
    GNUTLS_EXPORT_FLAG_NO_LZ = 1
}

alias gnutls_abstract_export_flags_t = gnutls_abstract_export_flags;

enum GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA = gnutls_certificate_verify_flags.GNUTLS_VERIFY_USE_TLS1_RSA;

alias gnutls_privkey_sign_func = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* raw_data, gnutls_datum_t* signature);

alias gnutls_privkey_decrypt_func = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* ciphertext, gnutls_datum_t* plaintext);

alias gnutls_privkey_decrypt_func2 = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* ciphertext, ubyte* plaintext, size_t plaintext_size);

alias gnutls_privkey_sign_hash_func = int function (gnutls_privkey_t key, gnutls_sign_algorithm_t algo, void* userdata, uint flags, const(gnutls_datum_t)* hash, gnutls_datum_t* signature);

alias gnutls_privkey_sign_data_func = int function (gnutls_privkey_t key, gnutls_sign_algorithm_t algo, void* userdata, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);

alias gnutls_privkey_deinit_func = void function (gnutls_privkey_t key, void* userdata);

extern (D) auto GNUTLS_SIGN_ALGO_TO_FLAGS(T)(auto ref T sig)
{
    return cast(uint) sig << 20;
}

extern (D) auto GNUTLS_FLAGS_TO_SIGN_ALGO(T)(auto ref T flags)
{
    return cast(uint) flags >> 20;
}

enum GNUTLS_PRIVKEY_INFO_PK_ALGO = 1;

enum GNUTLS_PRIVKEY_INFO_SIGN_ALGO = 1 << 1;

enum GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO = 1 << 2;

enum GNUTLS_PRIVKEY_INFO_PK_ALGO_BITS = 1 << 3;

alias gnutls_privkey_info_func = int function (gnutls_privkey_t key, uint flags, void* userdata);

int gnutls_pubkey_init (gnutls_pubkey_t* key);
void gnutls_pubkey_deinit (gnutls_pubkey_t key);

int gnutls_pubkey_verify_params (gnutls_pubkey_t key);

void gnutls_pubkey_set_pin_function (gnutls_pubkey_t key, gnutls_pin_callback_t fn, void* userdata);

int gnutls_pubkey_get_pk_algorithm (gnutls_pubkey_t key, uint* bits);

int gnutls_pubkey_set_spki (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);

int gnutls_pubkey_get_spki (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);

int gnutls_pubkey_import_x509 (gnutls_pubkey_t key, gnutls_x509_crt_t crt, uint flags);
int gnutls_pubkey_import_x509_crq (gnutls_pubkey_t key, gnutls_x509_crq_t crq, uint flags);
int gnutls_pubkey_import_pkcs11 (gnutls_pubkey_t key, gnutls_pkcs11_obj_t obj, uint flags);
int gnutls_pubkey_import_openpgp (gnutls_pubkey_t key, gnutls_openpgp_crt_t crt, uint flags);

int gnutls_pubkey_import_openpgp_raw (gnutls_pubkey_t pkey, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format, const gnutls_openpgp_keyid_t keyid, uint flags);
int gnutls_pubkey_import_x509_raw (gnutls_pubkey_t pkey, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);

int gnutls_pubkey_import_privkey (gnutls_pubkey_t key, gnutls_privkey_t pkey, uint usage, uint flags);

int gnutls_pubkey_import_tpm_url (gnutls_pubkey_t pkey, const(char)* url, const(char)* srk_password, uint flags);

int gnutls_pubkey_import_url (gnutls_pubkey_t key, const(char)* url, uint flags);

int gnutls_pubkey_import_tpm_raw (gnutls_pubkey_t pkey, const(gnutls_datum_t)* fdata, gnutls_tpmkey_fmt_t format, const(char)* srk_password, uint flags);

int gnutls_pubkey_get_preferred_hash_algorithm (gnutls_pubkey_t key, gnutls_digest_algorithm_t* hash, uint* mand);

alias gnutls_pubkey_get_pk_rsa_raw = gnutls_pubkey_export_rsa_raw;
int gnutls_pubkey_export_rsa_raw (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e);

int gnutls_pubkey_export_rsa_raw2 (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, uint flags);

alias gnutls_pubkey_get_pk_dsa_raw = gnutls_pubkey_export_dsa_raw;
int gnutls_pubkey_export_dsa_raw (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);

int gnutls_pubkey_export_dsa_raw2 (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, uint flags);

int gnutls_pubkey_export_ecc_raw2 (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);

int gnutls_pubkey_export_gost_raw2 (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);

alias gnutls_pubkey_get_pk_ecc_raw = gnutls_pubkey_export_ecc_raw;
int gnutls_pubkey_export_ecc_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y);

alias gnutls_pubkey_get_pk_ecc_x962 = gnutls_pubkey_export_ecc_x962;
int gnutls_pubkey_export_ecc_x962 (gnutls_pubkey_t key, gnutls_datum_t* parameters, gnutls_datum_t* ecpoint);

int gnutls_pubkey_export (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);

int gnutls_pubkey_export2 (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);

int gnutls_pubkey_get_key_id (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size);

int gnutls_pubkey_get_openpgp_key_id (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size, uint* subkey);

int gnutls_pubkey_get_key_usage (gnutls_pubkey_t key, uint* usage);
int gnutls_pubkey_set_key_usage (gnutls_pubkey_t key, uint usage);

int gnutls_pubkey_import (gnutls_pubkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);

alias gnutls_pubkey_import_pkcs11_url = gnutls_pubkey_import_url;

int gnutls_pubkey_import_dsa_raw (gnutls_pubkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y);
int gnutls_pubkey_import_rsa_raw (gnutls_pubkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e);

int gnutls_pubkey_import_ecc_x962 (gnutls_pubkey_t key, const(gnutls_datum_t)* parameters, const(gnutls_datum_t)* ecpoint);

int gnutls_pubkey_import_ecc_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

int gnutls_pubkey_import_gost_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

int gnutls_pubkey_encrypt_data (gnutls_pubkey_t key, uint flags, const(gnutls_datum_t)* plaintext, gnutls_datum_t* ciphertext);

int gnutls_x509_crt_set_pubkey (gnutls_x509_crt_t crt, gnutls_pubkey_t key);

int gnutls_x509_crq_set_pubkey (gnutls_x509_crq_t crq, gnutls_pubkey_t key);

int gnutls_pubkey_verify_hash2 (gnutls_pubkey_t key, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash, const(gnutls_datum_t)* signature);

int gnutls_pubkey_verify_data2 (gnutls_pubkey_t pubkey, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, const(gnutls_datum_t)* signature);

int gnutls_privkey_init (gnutls_privkey_t* key);
void gnutls_privkey_deinit (gnutls_privkey_t key);

extern (D) auto GNUTLS_SUBGROUP_TO_BITS(T0, T1)(auto ref T0 group, auto ref T1 subgroup)
{
    return cast(uint) (subgroup << 16) | group;
}

extern (D) auto GNUTLS_BITS_TO_SUBGROUP(T)(auto ref T bits)
{
    return (bits >> 16) & 0xFFFF;
}

extern (D) auto GNUTLS_BITS_TO_GROUP(T)(auto ref T bits)
{
    return bits & 0xFFFF;
}

extern (D) auto GNUTLS_BITS_HAVE_SUBGROUP(T)(auto ref T bits)
{
    return bits & 0xFFFF0000;
}

int gnutls_privkey_generate (gnutls_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags);
int gnutls_privkey_generate2 (gnutls_privkey_t pkey, gnutls_pk_algorithm_t algo, uint bits, uint flags, const(gnutls_keygen_data_st)* data, uint data_size);

int gnutls_privkey_set_spki (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);

int gnutls_privkey_get_spki (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);

int gnutls_privkey_verify_seed (gnutls_privkey_t key, gnutls_digest_algorithm_t, const(void)* seed, size_t seed_size);
int gnutls_privkey_get_seed (gnutls_privkey_t key, gnutls_digest_algorithm_t*, void* seed, size_t* seed_size);

int gnutls_privkey_verify_params (gnutls_privkey_t key);

void gnutls_privkey_set_flags (gnutls_privkey_t key, uint flags);

void gnutls_privkey_set_pin_function (gnutls_privkey_t key, gnutls_pin_callback_t fn, void* userdata);

int gnutls_privkey_get_pk_algorithm (gnutls_privkey_t key, uint* bits);
gnutls_privkey_type_t gnutls_privkey_get_type (gnutls_privkey_t key);
int gnutls_privkey_status (gnutls_privkey_t key);

enum gnutls_privkey_flags
{
    GNUTLS_PRIVKEY_IMPORT_AUTO_RELEASE = 1,
    GNUTLS_PRIVKEY_IMPORT_COPY = 1 << 1,
    GNUTLS_PRIVKEY_DISABLE_CALLBACKS = 1 << 2,
    GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA = 1 << 4,
    GNUTLS_PRIVKEY_FLAG_PROVABLE = 1 << 5,
    GNUTLS_PRIVKEY_FLAG_EXPORT_COMPAT = 1 << 6,
    GNUTLS_PRIVKEY_SIGN_FLAG_RSA_PSS = 1 << 7,
    GNUTLS_PRIVKEY_FLAG_REPRODUCIBLE = 1 << 8,
    GNUTLS_PRIVKEY_FLAG_CA = 1 << 9
}

alias gnutls_privkey_flags_t = gnutls_privkey_flags;

int gnutls_privkey_import_pkcs11 (gnutls_privkey_t pkey, gnutls_pkcs11_privkey_t key, uint flags);
int gnutls_privkey_import_x509 (gnutls_privkey_t pkey, gnutls_x509_privkey_t key, uint flags);
int gnutls_privkey_import_openpgp (gnutls_privkey_t pkey, gnutls_openpgp_privkey_t key, uint flags);

int gnutls_privkey_export_x509 (gnutls_privkey_t pkey, gnutls_x509_privkey_t* key);
int gnutls_privkey_export_openpgp (gnutls_privkey_t pkey, gnutls_openpgp_privkey_t* key);
int gnutls_privkey_export_pkcs11 (gnutls_privkey_t pkey, gnutls_pkcs11_privkey_t* key);

int gnutls_privkey_import_openpgp_raw (gnutls_privkey_t pkey, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format, const gnutls_openpgp_keyid_t keyid, const(char)* password);

int gnutls_privkey_import_x509_raw (gnutls_privkey_t pkey, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);

int gnutls_privkey_import_tpm_raw (gnutls_privkey_t pkey, const(gnutls_datum_t)* fdata, gnutls_tpmkey_fmt_t format, const(char)* srk_password, const(char)* key_password, uint flags);

int gnutls_privkey_import_tpm_url (gnutls_privkey_t pkey, const(char)* url, const(char)* srk_password, const(char)* key_password, uint flags);

int gnutls_privkey_import_url (gnutls_privkey_t key, const(char)* url, uint flags);

extern (D) auto gnutls_privkey_import_pkcs11_url(T0, T1)(auto ref T0 key, auto ref T1 url)
{
    return gnutls_privkey_import_url(key, url, 0);
}

int gnutls_privkey_import_ext (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, uint flags);

int gnutls_privkey_import_ext2 (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, uint flags);

int gnutls_privkey_import_ext3 (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

int gnutls_privkey_import_ext4 (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_data_func sign_data_func, gnutls_privkey_sign_hash_func sign_hash_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

int gnutls_privkey_import_dsa_raw (gnutls_privkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y, const(gnutls_datum_t)* x);

int gnutls_privkey_import_rsa_raw (gnutls_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u, const(gnutls_datum_t)* e1, const(gnutls_datum_t)* e2);
int gnutls_privkey_import_ecc_raw (gnutls_privkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

int gnutls_privkey_import_gost_raw (gnutls_privkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

int gnutls_privkey_sign_data (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);

int gnutls_privkey_sign_data2 (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);

extern (D) auto gnutls_privkey_sign_raw_data(T0, T1, T2, T3)(auto ref T0 key, auto ref T1 flags, auto ref T2 data, auto ref T3 sig)
{
    return gnutls_privkey_sign_hash(key, 0, gnutls_privkey_flags_t.GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA, data, sig);
}

int gnutls_privkey_sign_hash (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash_algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);

int gnutls_privkey_sign_hash2 (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);

int gnutls_privkey_decrypt_data (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, gnutls_datum_t* plaintext);

int gnutls_privkey_decrypt_data2 (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, ubyte* plaintext, size_t plaintext_size);

int gnutls_privkey_export_rsa_raw (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2);

int gnutls_privkey_export_rsa_raw2 (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2, uint flags);

int gnutls_privkey_export_dsa_raw (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);

int gnutls_privkey_export_dsa_raw2 (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x, uint flags);

int gnutls_privkey_export_ecc_raw (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);

int gnutls_privkey_export_ecc_raw2 (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);

int gnutls_privkey_export_gost_raw2 (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);

int gnutls_x509_crt_privkey_sign (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);

int gnutls_x509_crl_privkey_sign (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);

int gnutls_x509_crq_privkey_sign (gnutls_x509_crq_t crq, gnutls_privkey_t key, gnutls_digest_algorithm_t dig, uint flags);

struct gnutls_pcert_st
{
    gnutls_pubkey_t pubkey;
    gnutls_datum_t cert;
    gnutls_certificate_type_t type;
}

enum GNUTLS_PCERT_NO_CERT = 1;

int gnutls_pcert_import_x509 (gnutls_pcert_st* pcert, gnutls_x509_crt_t crt, uint flags);

int gnutls_pcert_import_x509_list (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt, uint* ncrt, uint flags);

int gnutls_pcert_export_x509 (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt);

int gnutls_pcert_list_import_x509_raw (gnutls_pcert_st* pcerts, uint* pcert_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);

int gnutls_pcert_list_import_x509_file (gnutls_pcert_st* pcert_list, uint* pcert_list_size, const(char)* file, gnutls_x509_crt_fmt_t format, gnutls_pin_callback_t pin_fn, void* pin_fn_userdata, uint flags);

int gnutls_pcert_import_x509_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_x509_crt_fmt_t format, uint flags);

int gnutls_pcert_import_openpgp_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_openpgp_crt_fmt_t format, gnutls_openpgp_keyid_t keyid, uint flags);

int gnutls_pcert_import_openpgp (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t crt, uint flags);

int gnutls_pcert_export_openpgp (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t* crt);

void gnutls_pcert_deinit (gnutls_pcert_st* pcert);

int gnutls_pcert_import_rawpk (gnutls_pcert_st* pcert, gnutls_pubkey_t key, uint flags);

int gnutls_pcert_import_rawpk_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* rawpubkey, gnutls_x509_crt_fmt_t format, uint key_usage, uint flags);

alias gnutls_certificate_retrieve_function2 = int function (gnutls_session_t, const(gnutls_datum_t)* req_ca_rdn, int nreqs, const(gnutls_pk_algorithm_t)* pk_algos, int pk_algos_length, gnutls_pcert_st**, uint* pcert_length, gnutls_privkey_t* privkey);

void gnutls_certificate_set_retrieve_function2 (gnutls_certificate_credentials_t cred, int function () func);

struct gnutls_cert_retr_st
{
    uint version_;
    gnutls_certificate_credentials_t cred;
    const(gnutls_datum_t)* req_ca_rdn;
    uint nreqs;
    const(gnutls_pk_algorithm_t)* pk_algos;
    uint pk_algos_length;

    ubyte[64] padding;
}

enum GNUTLS_CERT_RETR_DEINIT_ALL = 1;

alias gnutls_certificate_retrieve_function3 = int function (gnutls_session_t, const(gnutls_cert_retr_st)* info, gnutls_pcert_st** certs, uint* pcert_length, gnutls_ocsp_data_st** ocsp, uint* ocsp_length, gnutls_privkey_t* privkey, uint* flags);

void gnutls_certificate_set_retrieve_function3 (gnutls_certificate_credentials_t cred, int function () func);

int gnutls_certificate_set_key (gnutls_certificate_credentials_t res, const(char*)* names, int names_size, gnutls_pcert_st* pcert_list, int pcert_list_size, gnutls_privkey_t key);

int gnutls_pubkey_print (gnutls_pubkey_t pubkey, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
