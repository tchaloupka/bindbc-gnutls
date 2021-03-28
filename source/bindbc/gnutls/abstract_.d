module bindbc.gnutls.abstract_;

import bindbc.gnutls.config;
import bindbc.gnutls.gnutls;
import bindbc.gnutls.openpgp;
import bindbc.gnutls.pkcs11;
import bindbc.gnutls.tpm;
import bindbc.gnutls.x509;

enum GNUTLS_PUBKEY_VERIFY_FLAG_TLS_RSA = GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA;

enum gnutls_pubkey_flags
{
    GNUTLS_PUBKEY_DISABLE_CALLBACKS = 1 << 2,
    GNUTLS_PUBKEY_GET_OPENPGP_FINGERPRINT = 1 << 3
}

alias gnutls_pubkey_flags_t = gnutls_pubkey_flags;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
{
    enum gnutls_abstract_export_flags
    {
        GNUTLS_EXPORT_FLAG_NO_LZ = 1
    }
    alias gnutls_abstract_export_flags_t = gnutls_abstract_export_flags;
}

enum GNUTLS_PUBKEY_VERIFY_FLAG_TLS1_RSA = gnutls_certificate_verify_flags.GNUTLS_VERIFY_USE_TLS1_RSA;

enum GNUTLS_PRIVKEY_INFO_PK_ALGO = 1;
enum GNUTLS_PRIVKEY_INFO_SIGN_ALGO = 1 << 1;
enum GNUTLS_PRIVKEY_INFO_HAVE_SIGN_ALGO = 1 << 2;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
    enum GNUTLS_PRIVKEY_INFO_PK_ALGO_BITS = 1 << 3;

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

struct gnutls_pcert_st
{
    gnutls_pubkey_t pubkey;
    gnutls_datum_t cert;
    gnutls_certificate_type_t type;
}

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_6)
{
    deprecated("This flag is unused/ignored, deprecated from GnuTLS 3.6.6; do not use")
    enum GNUTLS_PCERT_NO_CERT = 1;
}
else enum GNUTLS_PCERT_NO_CERT = 1;

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

extern(C) nothrow @nogc
{
    alias gnutls_privkey_sign_func = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* raw_data, gnutls_datum_t* signature);
    alias gnutls_privkey_decrypt_func = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* ciphertext, gnutls_datum_t* plaintext);
    alias gnutls_privkey_decrypt_func2 = int function (gnutls_privkey_t key, void* userdata, const(gnutls_datum_t)* ciphertext, ubyte* plaintext, size_t plaintext_size);
    alias gnutls_privkey_sign_hash_func = int function (gnutls_privkey_t key, gnutls_sign_algorithm_t algo, void* userdata, uint flags, const(gnutls_datum_t)* hash, gnutls_datum_t* signature);
    alias gnutls_privkey_sign_data_func = int function (gnutls_privkey_t key, gnutls_sign_algorithm_t algo, void* userdata, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);
    alias gnutls_privkey_deinit_func = void function (gnutls_privkey_t key, void* userdata);
    alias gnutls_privkey_info_func = int function (gnutls_privkey_t key, uint flags, void* userdata);
    alias gnutls_certificate_retrieve_function2 = int function (gnutls_session_t, const(gnutls_datum_t)* req_ca_rdn, int nreqs, const(gnutls_pk_algorithm_t)* pk_algos, int pk_algos_length, gnutls_pcert_st**, uint* pcert_length, gnutls_privkey_t* privkey);
    alias gnutls_certificate_retrieve_function3 = int function (gnutls_session_t, const(gnutls_cert_retr_st)* info, gnutls_pcert_st** certs, uint* pcert_length, gnutls_ocsp_data_st** ocsp, uint* ocsp_length, gnutls_privkey_t* privkey, uint* flags);
}

extern (D) nothrow @nogc
{
    uint GNUTLS_SIGN_ALGO_TO_FLAGS(uint sig) @safe pure
    {
        return cast(uint) sig << 20;
    }

    uint GNUTLS_FLAGS_TO_SIGN_ALGO(uint flags) @safe pure
    {
        return cast(uint) flags >> 20;
    }

    uint GNUTLS_SUBGROUP_TO_BITS(uint group, uint subgroup) @safe pure
    {
        return cast(uint) (subgroup << 16) | group;
    }

    uint GNUTLS_BITS_TO_SUBGROUP(uint bits) @safe pure
    {
        return (bits >> 16) & 0xFFFF;
    }

    uint GNUTLS_BITS_TO_GROUP(uint bits) @safe pure
    {
        return bits & 0xFFFF;
    }

    uint GNUTLS_BITS_HAVE_SUBGROUP(uint bits) @safe pure
    {
        return bits & 0xFFFF0000;
    }

    int gnutls_privkey_import_pkcs11_url(gnutls_privkey_t key, const(char)* url)
    {
        return gnutls_privkey_import_url(key, url, 0);
    }

    int gnutls_privkey_sign_raw_data(gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* sig)
    {
        return gnutls_privkey_sign_hash(key, gnutls_digest_algorithm_t.GNUTLS_DIG_UNKNOWN, gnutls_privkey_flags_t.GNUTLS_PRIVKEY_SIGN_FLAG_TLS1_RSA, data, sig);
    }
}

alias gnutls_pubkey_get_pk_rsa_raw = gnutls_pubkey_export_rsa_raw;
alias gnutls_pubkey_get_pk_dsa_raw = gnutls_pubkey_export_dsa_raw;
alias gnutls_pubkey_get_pk_ecc_raw = gnutls_pubkey_export_ecc_raw;
alias gnutls_pubkey_get_pk_ecc_x962 = gnutls_pubkey_export_ecc_x962;
alias gnutls_pubkey_import_pkcs11_url = gnutls_pubkey_import_url;

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_pubkey_init (gnutls_pubkey_t* key);
    void gnutls_pubkey_deinit (gnutls_pubkey_t key);
    int gnutls_pubkey_verify_params (gnutls_pubkey_t key);
    void gnutls_pubkey_set_pin_function (gnutls_pubkey_t key, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_pubkey_get_pk_algorithm (gnutls_pubkey_t key, uint* bits);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_pubkey_set_spki (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);
        int gnutls_pubkey_get_spki (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);
    }

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
    int gnutls_pubkey_export_rsa_raw (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e);
    int gnutls_pubkey_export_dsa_raw (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_pubkey_export_rsa_raw2 (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, uint flags);
        int gnutls_pubkey_export_dsa_raw2 (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, uint flags);
        int gnutls_pubkey_export_ecc_raw2 (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);
    }

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_pubkey_export_gost_raw2 (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);

    int gnutls_pubkey_export_ecc_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y);
    int gnutls_pubkey_export_ecc_x962 (gnutls_pubkey_t key, gnutls_datum_t* parameters, gnutls_datum_t* ecpoint);
    int gnutls_pubkey_export (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_pubkey_export2 (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_pubkey_get_key_id (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size);
    int gnutls_pubkey_get_openpgp_key_id (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size, uint* subkey);
    int gnutls_pubkey_get_key_usage (gnutls_pubkey_t key, uint* usage);
    int gnutls_pubkey_set_key_usage (gnutls_pubkey_t key, uint usage);
    int gnutls_pubkey_import (gnutls_pubkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_pubkey_import_dsa_raw (gnutls_pubkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y);
    int gnutls_pubkey_import_rsa_raw (gnutls_pubkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e);
    int gnutls_pubkey_import_ecc_x962 (gnutls_pubkey_t key, const(gnutls_datum_t)* parameters, const(gnutls_datum_t)* ecpoint);
    int gnutls_pubkey_import_ecc_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_pubkey_import_gost_raw (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

    int gnutls_pubkey_encrypt_data (gnutls_pubkey_t key, uint flags, const(gnutls_datum_t)* plaintext, gnutls_datum_t* ciphertext);
    int gnutls_x509_crt_set_pubkey (gnutls_x509_crt_t crt, gnutls_pubkey_t key);
    int gnutls_x509_crq_set_pubkey (gnutls_x509_crq_t crq, gnutls_pubkey_t key);
    int gnutls_pubkey_verify_hash2 (gnutls_pubkey_t key, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash, const(gnutls_datum_t)* signature);
    int gnutls_pubkey_verify_data2 (gnutls_pubkey_t pubkey, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, const(gnutls_datum_t)* signature);
    int gnutls_privkey_init (gnutls_privkey_t* key);
    void gnutls_privkey_deinit (gnutls_privkey_t key);
    int gnutls_privkey_generate (gnutls_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags);
    int gnutls_privkey_generate2 (gnutls_privkey_t pkey, gnutls_pk_algorithm_t algo, uint bits, uint flags, const(gnutls_keygen_data_st)* data, uint data_size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_privkey_set_spki (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
        int gnutls_privkey_get_spki (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
    }

    int gnutls_privkey_verify_seed (gnutls_privkey_t key, gnutls_digest_algorithm_t, const(void)* seed, size_t seed_size);
    int gnutls_privkey_get_seed (gnutls_privkey_t key, gnutls_digest_algorithm_t*, void* seed, size_t* seed_size);
    int gnutls_privkey_verify_params (gnutls_privkey_t key);
    void gnutls_privkey_set_flags (gnutls_privkey_t key, uint flags);
    void gnutls_privkey_set_pin_function (gnutls_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_privkey_get_pk_algorithm (gnutls_privkey_t key, uint* bits);
    gnutls_privkey_type_t gnutls_privkey_get_type (gnutls_privkey_t key);
    int gnutls_privkey_status (gnutls_privkey_t key);
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
    int gnutls_privkey_import_ext (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, uint flags);
    int gnutls_privkey_import_ext2 (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, uint flags);
    int gnutls_privkey_import_ext3 (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        int gnutls_privkey_import_ext4 (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_data_func sign_data_func, gnutls_privkey_sign_hash_func sign_hash_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

    int gnutls_privkey_import_dsa_raw (gnutls_privkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y, const(gnutls_datum_t)* x);
    int gnutls_privkey_import_rsa_raw (gnutls_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u, const(gnutls_datum_t)* e1, const(gnutls_datum_t)* e2);
    int gnutls_privkey_import_ecc_raw (gnutls_privkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_privkey_import_gost_raw (gnutls_privkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

    int gnutls_privkey_sign_data (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);
    int gnutls_privkey_sign_data2 (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);
    int gnutls_privkey_sign_hash (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash_algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);
    int gnutls_privkey_sign_hash2 (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);
    int gnutls_privkey_decrypt_data (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, gnutls_datum_t* plaintext);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        int gnutls_privkey_decrypt_data2 (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, ubyte* plaintext, size_t plaintext_size);

    int gnutls_privkey_export_rsa_raw (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2);
    int gnutls_privkey_export_dsa_raw (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
    int gnutls_privkey_export_ecc_raw (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_privkey_export_rsa_raw2 (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2, uint flags);
        int gnutls_privkey_export_dsa_raw2 (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x, uint flags);
        int gnutls_privkey_export_ecc_raw2 (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);
    }

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_privkey_export_gost_raw2 (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);

    int gnutls_x509_crt_privkey_sign (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_x509_crl_privkey_sign (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_x509_crq_privkey_sign (gnutls_x509_crq_t crq, gnutls_privkey_t key, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_pcert_import_x509 (gnutls_pcert_st* pcert, gnutls_x509_crt_t crt, uint flags);
    int gnutls_pcert_import_x509_list (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt, uint* ncrt, uint flags);
    int gnutls_pcert_export_x509 (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt);
    int gnutls_pcert_list_import_x509_raw (gnutls_pcert_st* pcerts, uint* pcert_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_pcert_list_import_x509_file (gnutls_pcert_st* pcert_list, uint* pcert_list_size, const(char)* file, gnutls_x509_crt_fmt_t format, gnutls_pin_callback_t pin_fn, void* pin_fn_userdata, uint flags);

    int gnutls_pcert_import_x509_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_pcert_import_openpgp_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_openpgp_crt_fmt_t format, gnutls_openpgp_keyid_t keyid, uint flags);
    int gnutls_pcert_import_openpgp (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t crt, uint flags);
    int gnutls_pcert_export_openpgp (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t* crt);
    void gnutls_pcert_deinit (gnutls_pcert_st* pcert);
    int gnutls_pcert_import_rawpk (gnutls_pcert_st* pcert, gnutls_pubkey_t key, uint flags);
    int gnutls_pcert_import_rawpk_raw (gnutls_pcert_st* pcert, const(gnutls_datum_t)* rawpubkey, gnutls_x509_crt_fmt_t format, uint key_usage, uint flags);
    void gnutls_certificate_set_retrieve_function2 (gnutls_certificate_credentials_t cred, int function () func);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        void gnutls_certificate_set_retrieve_function3 (gnutls_certificate_credentials_t cred, int function () func);

    int gnutls_certificate_set_key (gnutls_certificate_credentials_t res, const(char*)* names, int names_size, gnutls_pcert_st* pcert_list, int pcert_list_size, gnutls_privkey_t key);
    int gnutls_pubkey_print (gnutls_pubkey_t pubkey, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_pubkey_init = int function (gnutls_pubkey_t* key);
        alias pgnutls_pubkey_deinit = void function (gnutls_pubkey_t key);
        alias pgnutls_pubkey_verify_params = int function (gnutls_pubkey_t key);
        alias pgnutls_pubkey_set_pin_function = void function (gnutls_pubkey_t key, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_pubkey_get_pk_algorithm = int function (gnutls_pubkey_t key, uint* bits);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_pubkey_set_spki = int function (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);
            alias pgnutls_pubkey_get_spki = int function (gnutls_pubkey_t key, const gnutls_x509_spki_t spki, uint flags);
        }

        alias pgnutls_pubkey_import_x509 = int function (gnutls_pubkey_t key, gnutls_x509_crt_t crt, uint flags);
        alias pgnutls_pubkey_import_x509_crq = int function (gnutls_pubkey_t key, gnutls_x509_crq_t crq, uint flags);
        alias pgnutls_pubkey_import_pkcs11 = int function (gnutls_pubkey_t key, gnutls_pkcs11_obj_t obj, uint flags);
        alias pgnutls_pubkey_import_openpgp = int function (gnutls_pubkey_t key, gnutls_openpgp_crt_t crt, uint flags);
        alias pgnutls_pubkey_import_openpgp_raw = int function (gnutls_pubkey_t pkey, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format, const gnutls_openpgp_keyid_t keyid, uint flags);
        alias pgnutls_pubkey_import_x509_raw = int function (gnutls_pubkey_t pkey, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_pubkey_import_privkey = int function (gnutls_pubkey_t key, gnutls_privkey_t pkey, uint usage, uint flags);
        alias pgnutls_pubkey_import_tpm_url = int function (gnutls_pubkey_t pkey, const(char)* url, const(char)* srk_password, uint flags);
        alias pgnutls_pubkey_import_url = int function (gnutls_pubkey_t key, const(char)* url, uint flags);
        alias pgnutls_pubkey_import_tpm_raw = int function (gnutls_pubkey_t pkey, const(gnutls_datum_t)* fdata, gnutls_tpmkey_fmt_t format, const(char)* srk_password, uint flags);
        alias pgnutls_pubkey_get_preferred_hash_algorithm = int function (gnutls_pubkey_t key, gnutls_digest_algorithm_t* hash, uint* mand);
        alias pgnutls_pubkey_export_rsa_raw = int function (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e);
        alias pgnutls_pubkey_export_dsa_raw = int function (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_pubkey_export_rsa_raw2 = int function (gnutls_pubkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, uint flags);
            alias pgnutls_pubkey_export_dsa_raw2 = int function (gnutls_pubkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, uint flags);
            alias pgnutls_pubkey_export_ecc_raw2 = int function (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_pubkey_export_gost_raw2 = int function (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, uint flags);

        alias pgnutls_pubkey_export_ecc_raw = int function (gnutls_pubkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y);
        alias pgnutls_pubkey_export_ecc_x962 = int function (gnutls_pubkey_t key, gnutls_datum_t* parameters, gnutls_datum_t* ecpoint);
        alias pgnutls_pubkey_export = int function (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_pubkey_export2 = int function (gnutls_pubkey_t key, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_pubkey_get_key_id = int function (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size);
        alias pgnutls_pubkey_get_openpgp_key_id = int function (gnutls_pubkey_t key, uint flags, ubyte* output_data, size_t* output_data_size, uint* subkey);
        alias pgnutls_pubkey_get_key_usage = int function (gnutls_pubkey_t key, uint* usage);
        alias pgnutls_pubkey_set_key_usage = int function (gnutls_pubkey_t key, uint usage);
        alias pgnutls_pubkey_import = int function (gnutls_pubkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_pubkey_import_dsa_raw = int function (gnutls_pubkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y);
        alias pgnutls_pubkey_import_rsa_raw = int function (gnutls_pubkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e);
        alias pgnutls_pubkey_import_ecc_x962 = int function (gnutls_pubkey_t key, const(gnutls_datum_t)* parameters, const(gnutls_datum_t)* ecpoint);
        alias pgnutls_pubkey_import_ecc_raw = int function (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_pubkey_import_gost_raw = int function (gnutls_pubkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y);

        alias pgnutls_pubkey_encrypt_data = int function (gnutls_pubkey_t key, uint flags, const(gnutls_datum_t)* plaintext, gnutls_datum_t* ciphertext);
        alias pgnutls_x509_crt_set_pubkey = int function (gnutls_x509_crt_t crt, gnutls_pubkey_t key);
        alias pgnutls_x509_crq_set_pubkey = int function (gnutls_x509_crq_t crq, gnutls_pubkey_t key);
        alias pgnutls_pubkey_verify_hash2 = int function (gnutls_pubkey_t key, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash, const(gnutls_datum_t)* signature);
        alias pgnutls_pubkey_verify_data2 = int function (gnutls_pubkey_t pubkey, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, const(gnutls_datum_t)* signature);
        alias pgnutls_privkey_init = int function (gnutls_privkey_t* key);
        alias pgnutls_privkey_deinit = void function (gnutls_privkey_t key);
        alias pgnutls_privkey_generate = int function (gnutls_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags);
        alias pgnutls_privkey_generate2 = int function (gnutls_privkey_t pkey, gnutls_pk_algorithm_t algo, uint bits, uint flags, const(gnutls_keygen_data_st)* data, uint data_size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_privkey_set_spki = int function (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
            alias pgnutls_privkey_get_spki = int function (gnutls_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
        }

        alias pgnutls_privkey_verify_seed = int function (gnutls_privkey_t key, gnutls_digest_algorithm_t, const(void)* seed, size_t seed_size);
        alias pgnutls_privkey_get_seed = int function (gnutls_privkey_t key, gnutls_digest_algorithm_t*, void* seed, size_t* seed_size);
        alias pgnutls_privkey_verify_params = int function (gnutls_privkey_t key);
        alias pgnutls_privkey_set_flags = void function (gnutls_privkey_t key, uint flags);
        alias pgnutls_privkey_set_pin_function = void function (gnutls_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_privkey_get_pk_algorithm = int function (gnutls_privkey_t key, uint* bits);
        alias pgnutls_privkey_get_type = gnutls_privkey_type_t function (gnutls_privkey_t key);
        alias pgnutls_privkey_status = int function (gnutls_privkey_t key);
        alias pgnutls_privkey_import_pkcs11 = int function (gnutls_privkey_t pkey, gnutls_pkcs11_privkey_t key, uint flags);
        alias pgnutls_privkey_import_x509 = int function (gnutls_privkey_t pkey, gnutls_x509_privkey_t key, uint flags);
        alias pgnutls_privkey_import_openpgp = int function (gnutls_privkey_t pkey, gnutls_openpgp_privkey_t key, uint flags);
        alias pgnutls_privkey_export_x509 = int function (gnutls_privkey_t pkey, gnutls_x509_privkey_t* key);
        alias pgnutls_privkey_export_openpgp = int function (gnutls_privkey_t pkey, gnutls_openpgp_privkey_t* key);
        alias pgnutls_privkey_export_pkcs11 = int function (gnutls_privkey_t pkey, gnutls_pkcs11_privkey_t* key);
        alias pgnutls_privkey_import_openpgp_raw = int function (gnutls_privkey_t pkey, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format, const gnutls_openpgp_keyid_t keyid, const(char)* password);
        alias pgnutls_privkey_import_x509_raw = int function (gnutls_privkey_t pkey, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);
        alias pgnutls_privkey_import_tpm_raw = int function (gnutls_privkey_t pkey, const(gnutls_datum_t)* fdata, gnutls_tpmkey_fmt_t format, const(char)* srk_password, const(char)* key_password, uint flags);
        alias pgnutls_privkey_import_tpm_url = int function (gnutls_privkey_t pkey, const(char)* url, const(char)* srk_password, const(char)* key_password, uint flags);
        alias pgnutls_privkey_import_url = int function (gnutls_privkey_t key, const(char)* url, uint flags);
        alias pgnutls_privkey_import_ext = int function (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, uint flags);
        alias pgnutls_privkey_import_ext2 = int function (gnutls_privkey_t pkey, gnutls_pk_algorithm_t pk, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, uint flags);
        alias pgnutls_privkey_import_ext3 = int function (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_func sign_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            alias pgnutls_privkey_import_ext4 = int function (gnutls_privkey_t pkey, void* userdata, gnutls_privkey_sign_data_func sign_data_func, gnutls_privkey_sign_hash_func sign_hash_func, gnutls_privkey_decrypt_func decrypt_func, gnutls_privkey_deinit_func deinit_func, gnutls_privkey_info_func info_func, uint flags);

        alias pgnutls_privkey_import_dsa_raw = int function (gnutls_privkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y, const(gnutls_datum_t)* x);
        alias pgnutls_privkey_import_rsa_raw = int function (gnutls_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u, const(gnutls_datum_t)* e1, const(gnutls_datum_t)* e2);
        alias pgnutls_privkey_import_ecc_raw = int function (gnutls_privkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_privkey_import_gost_raw = int function (gnutls_privkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);

        alias pgnutls_privkey_sign_data = int function (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);
        alias pgnutls_privkey_sign_data2 = int function (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, gnutls_datum_t* signature);
        alias pgnutls_privkey_sign_hash = int function (gnutls_privkey_t signer, gnutls_digest_algorithm_t hash_algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);
        alias pgnutls_privkey_sign_hash2 = int function (gnutls_privkey_t signer, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* hash_data, gnutls_datum_t* signature);
        alias pgnutls_privkey_decrypt_data = int function (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, gnutls_datum_t* plaintext);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            alias pgnutls_privkey_decrypt_data2 = int function (gnutls_privkey_t key, uint flags, const(gnutls_datum_t)* ciphertext, ubyte* plaintext, size_t plaintext_size);

        alias pgnutls_privkey_export_rsa_raw = int function (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2);
        alias pgnutls_privkey_export_dsa_raw = int function (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
        alias pgnutls_privkey_export_ecc_raw = int function (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_privkey_export_rsa_raw2 = int function (gnutls_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2, uint flags);
            alias pgnutls_privkey_export_dsa_raw2 = int function (gnutls_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x, uint flags);
            alias pgnutls_privkey_export_ecc_raw2 = int function (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_privkey_export_gost_raw2 = int function (gnutls_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k, uint flags);

        alias pgnutls_x509_crt_privkey_sign = int function (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_x509_crl_privkey_sign = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_x509_crq_privkey_sign = int function (gnutls_x509_crq_t crq, gnutls_privkey_t key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_pcert_import_x509 = int function (gnutls_pcert_st* pcert, gnutls_x509_crt_t crt, uint flags);
        alias pgnutls_pcert_import_x509_list = int function (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt, uint* ncrt, uint flags);
        alias pgnutls_pcert_export_x509 = int function (gnutls_pcert_st* pcert, gnutls_x509_crt_t* crt);
        alias pgnutls_pcert_list_import_x509_raw = int function (gnutls_pcert_st* pcerts, uint* pcert_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_pcert_list_import_x509_file = int function (gnutls_pcert_st* pcert_list, uint* pcert_list_size, const(char)* file, gnutls_x509_crt_fmt_t format, gnutls_pin_callback_t pin_fn, void* pin_fn_userdata, uint flags);

        alias pgnutls_pcert_import_x509_raw = int function (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_pcert_import_openpgp_raw = int function (gnutls_pcert_st* pcert, const(gnutls_datum_t)* cert, gnutls_openpgp_crt_fmt_t format, gnutls_openpgp_keyid_t keyid, uint flags);
        alias pgnutls_pcert_import_openpgp = int function (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t crt, uint flags);
        alias pgnutls_pcert_export_openpgp = int function (gnutls_pcert_st* pcert, gnutls_openpgp_crt_t* crt);
        alias pgnutls_pcert_deinit = void function (gnutls_pcert_st* pcert);
        alias pgnutls_pcert_import_rawpk = int function (gnutls_pcert_st* pcert, gnutls_pubkey_t key, uint flags);
        alias pgnutls_pcert_import_rawpk_raw = int function (gnutls_pcert_st* pcert, const(gnutls_datum_t)* rawpubkey, gnutls_x509_crt_fmt_t format, uint key_usage, uint flags);
        alias pgnutls_certificate_set_retrieve_function2 = void function (gnutls_certificate_credentials_t cred, int function () func);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_certificate_set_retrieve_function3 = void function (gnutls_certificate_credentials_t cred, int function () func);

        alias pgnutls_certificate_set_key = int function (gnutls_certificate_credentials_t res, const(char*)* names, int names_size, gnutls_pcert_st* pcert_list, int pcert_list_size, gnutls_privkey_t key);
        alias pgnutls_pubkey_print = int function (gnutls_pubkey_t pubkey, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    }

    __gshared
    {
        pgnutls_pubkey_init gnutls_pubkey_init;
        pgnutls_pubkey_deinit gnutls_pubkey_deinit;
        pgnutls_pubkey_verify_params gnutls_pubkey_verify_params;
        pgnutls_pubkey_set_pin_function gnutls_pubkey_set_pin_function;
        pgnutls_pubkey_get_pk_algorithm gnutls_pubkey_get_pk_algorithm;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_pubkey_set_spki gnutls_pubkey_set_spki;
            pgnutls_pubkey_get_spki gnutls_pubkey_get_spki;
        }

        pgnutls_pubkey_import_x509 gnutls_pubkey_import_x509;
        pgnutls_pubkey_import_x509_crq gnutls_pubkey_import_x509_crq;
        pgnutls_pubkey_import_pkcs11 gnutls_pubkey_import_pkcs11;
        pgnutls_pubkey_import_openpgp gnutls_pubkey_import_openpgp;
        pgnutls_pubkey_import_openpgp_raw gnutls_pubkey_import_openpgp_raw;
        pgnutls_pubkey_import_x509_raw gnutls_pubkey_import_x509_raw;
        pgnutls_pubkey_import_privkey gnutls_pubkey_import_privkey;
        pgnutls_pubkey_import_tpm_url gnutls_pubkey_import_tpm_url;
        pgnutls_pubkey_import_url gnutls_pubkey_import_url;
        pgnutls_pubkey_import_tpm_raw gnutls_pubkey_import_tpm_raw;
        pgnutls_pubkey_get_preferred_hash_algorithm gnutls_pubkey_get_preferred_hash_algorithm;
        pgnutls_pubkey_export_rsa_raw gnutls_pubkey_export_rsa_raw;
        pgnutls_pubkey_export_dsa_raw gnutls_pubkey_export_dsa_raw;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_pubkey_export_rsa_raw2 gnutls_pubkey_export_rsa_raw2;
            pgnutls_pubkey_export_dsa_raw2 gnutls_pubkey_export_dsa_raw2;
            pgnutls_pubkey_export_ecc_raw2 gnutls_pubkey_export_ecc_raw2;
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_pubkey_export_gost_raw2 gnutls_pubkey_export_gost_raw2;

        pgnutls_pubkey_export_ecc_raw gnutls_pubkey_export_ecc_raw;
        pgnutls_pubkey_export_ecc_x962 gnutls_pubkey_export_ecc_x962;
        pgnutls_pubkey_export gnutls_pubkey_export;
        pgnutls_pubkey_export2 gnutls_pubkey_export2;
        pgnutls_pubkey_get_key_id gnutls_pubkey_get_key_id;
        pgnutls_pubkey_get_openpgp_key_id gnutls_pubkey_get_openpgp_key_id;
        pgnutls_pubkey_get_key_usage gnutls_pubkey_get_key_usage;
        pgnutls_pubkey_set_key_usage gnutls_pubkey_set_key_usage;
        pgnutls_pubkey_import gnutls_pubkey_import;
        pgnutls_pubkey_import_dsa_raw gnutls_pubkey_import_dsa_raw;
        pgnutls_pubkey_import_rsa_raw gnutls_pubkey_import_rsa_raw;
        pgnutls_pubkey_import_ecc_x962 gnutls_pubkey_import_ecc_x962;
        pgnutls_pubkey_import_ecc_raw gnutls_pubkey_import_ecc_raw;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_pubkey_import_gost_raw gnutls_pubkey_import_gost_raw;

        pgnutls_pubkey_encrypt_data gnutls_pubkey_encrypt_data;
        pgnutls_x509_crt_set_pubkey gnutls_x509_crt_set_pubkey;
        pgnutls_x509_crq_set_pubkey gnutls_x509_crq_set_pubkey;
        pgnutls_pubkey_verify_hash2 gnutls_pubkey_verify_hash2;
        pgnutls_pubkey_verify_data2 gnutls_pubkey_verify_data2;
        pgnutls_privkey_init gnutls_privkey_init;
        pgnutls_privkey_deinit gnutls_privkey_deinit;
        pgnutls_privkey_generate gnutls_privkey_generate;
        pgnutls_privkey_generate2 gnutls_privkey_generate2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_privkey_set_spki gnutls_privkey_set_spki;
            pgnutls_privkey_get_spki gnutls_privkey_get_spki;
        }

        pgnutls_privkey_verify_seed gnutls_privkey_verify_seed;
        pgnutls_privkey_get_seed gnutls_privkey_get_seed;
        pgnutls_privkey_verify_params gnutls_privkey_verify_params;
        pgnutls_privkey_set_flags gnutls_privkey_set_flags;
        pgnutls_privkey_set_pin_function gnutls_privkey_set_pin_function;
        pgnutls_privkey_get_pk_algorithm gnutls_privkey_get_pk_algorithm;
        pgnutls_privkey_get_type gnutls_privkey_get_type;
        pgnutls_privkey_status gnutls_privkey_status;
        pgnutls_privkey_import_pkcs11 gnutls_privkey_import_pkcs11;
        pgnutls_privkey_import_x509 gnutls_privkey_import_x509;
        pgnutls_privkey_import_openpgp gnutls_privkey_import_openpgp;
        pgnutls_privkey_export_x509 gnutls_privkey_export_x509;
        pgnutls_privkey_export_openpgp gnutls_privkey_export_openpgp;
        pgnutls_privkey_export_pkcs11 gnutls_privkey_export_pkcs11;
        pgnutls_privkey_import_openpgp_raw gnutls_privkey_import_openpgp_raw;
        pgnutls_privkey_import_x509_raw gnutls_privkey_import_x509_raw;
        pgnutls_privkey_import_tpm_raw gnutls_privkey_import_tpm_raw;
        pgnutls_privkey_import_tpm_url gnutls_privkey_import_tpm_url;
        pgnutls_privkey_import_url gnutls_privkey_import_url;
        pgnutls_privkey_import_ext gnutls_privkey_import_ext;
        pgnutls_privkey_import_ext2 gnutls_privkey_import_ext2;
        pgnutls_privkey_import_ext3 gnutls_privkey_import_ext3;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            pgnutls_privkey_import_ext4 gnutls_privkey_import_ext4;

        pgnutls_privkey_import_dsa_raw gnutls_privkey_import_dsa_raw;
        pgnutls_privkey_import_rsa_raw gnutls_privkey_import_rsa_raw;
        pgnutls_privkey_import_ecc_raw gnutls_privkey_import_ecc_raw;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_privkey_import_gost_raw gnutls_privkey_import_gost_raw;

        pgnutls_privkey_sign_data gnutls_privkey_sign_data;
        pgnutls_privkey_sign_data2 gnutls_privkey_sign_data2;
        pgnutls_privkey_sign_hash gnutls_privkey_sign_hash;
        pgnutls_privkey_sign_hash2 gnutls_privkey_sign_hash2;
        pgnutls_privkey_decrypt_data gnutls_privkey_decrypt_data;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            pgnutls_privkey_decrypt_data2 gnutls_privkey_decrypt_data2;

        pgnutls_privkey_export_rsa_raw gnutls_privkey_export_rsa_raw;
        pgnutls_privkey_export_dsa_raw gnutls_privkey_export_dsa_raw;
        pgnutls_privkey_export_ecc_raw gnutls_privkey_export_ecc_raw;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_privkey_export_rsa_raw2 gnutls_privkey_export_rsa_raw2;
            pgnutls_privkey_export_dsa_raw2 gnutls_privkey_export_dsa_raw2;
            pgnutls_privkey_export_ecc_raw2 gnutls_privkey_export_ecc_raw2;
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_privkey_export_gost_raw2 gnutls_privkey_export_gost_raw2;

        pgnutls_x509_crt_privkey_sign gnutls_x509_crt_privkey_sign;
        pgnutls_x509_crl_privkey_sign gnutls_x509_crl_privkey_sign;
        pgnutls_x509_crq_privkey_sign gnutls_x509_crq_privkey_sign;
        pgnutls_pcert_import_x509 gnutls_pcert_import_x509;
        pgnutls_pcert_import_x509_list gnutls_pcert_import_x509_list;
        pgnutls_pcert_export_x509 gnutls_pcert_export_x509;
        pgnutls_pcert_list_import_x509_raw gnutls_pcert_list_import_x509_raw;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_pcert_list_import_x509_file gnutls_pcert_list_import_x509_file;

        pgnutls_pcert_import_x509_raw gnutls_pcert_import_x509_raw;
        pgnutls_pcert_import_openpgp_raw gnutls_pcert_import_openpgp_raw;
        pgnutls_pcert_import_openpgp gnutls_pcert_import_openpgp;
        pgnutls_pcert_export_openpgp gnutls_pcert_export_openpgp;
        pgnutls_pcert_deinit gnutls_pcert_deinit;
        pgnutls_pcert_import_rawpk gnutls_pcert_import_rawpk;
        pgnutls_pcert_import_rawpk_raw gnutls_pcert_import_rawpk_raw;
        pgnutls_certificate_set_retrieve_function2 gnutls_certificate_set_retrieve_function2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_certificate_set_retrieve_function3 gnutls_certificate_set_retrieve_function3;

        pgnutls_certificate_set_key gnutls_certificate_set_key;
        pgnutls_pubkey_print gnutls_pubkey_print;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindAbstract(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_pubkey_init, "gnutls_pubkey_init");
        lib.bindSymbol_stdcall(gnutls_pubkey_deinit, "gnutls_pubkey_deinit");
        lib.bindSymbol_stdcall(gnutls_pubkey_verify_params, "gnutls_pubkey_verify_params");
        lib.bindSymbol_stdcall(gnutls_pubkey_set_pin_function, "gnutls_pubkey_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_pubkey_get_pk_algorithm, "gnutls_pubkey_get_pk_algorithm");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_pubkey_set_spki, "gnutls_pubkey_set_spki");
            lib.bindSymbol_stdcall(gnutls_pubkey_get_spki, "gnutls_pubkey_get_spki");
        }

        lib.bindSymbol_stdcall(gnutls_pubkey_import_x509, "gnutls_pubkey_import_x509");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_x509_crq, "gnutls_pubkey_import_x509_crq");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_pkcs11, "gnutls_pubkey_import_pkcs11");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_openpgp, "gnutls_pubkey_import_openpgp");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_openpgp_raw, "gnutls_pubkey_import_openpgp_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_x509_raw, "gnutls_pubkey_import_x509_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_privkey, "gnutls_pubkey_import_privkey");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_tpm_url, "gnutls_pubkey_import_tpm_url");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_url, "gnutls_pubkey_import_url");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_tpm_raw, "gnutls_pubkey_import_tpm_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_get_preferred_hash_algorithm, "gnutls_pubkey_get_preferred_hash_algorithm");
        lib.bindSymbol_stdcall(gnutls_pubkey_export_rsa_raw, "gnutls_pubkey_export_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_export_dsa_raw, "gnutls_pubkey_export_dsa_raw");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_pubkey_export_rsa_raw2, "gnutls_pubkey_export_rsa_raw2");
            lib.bindSymbol_stdcall(gnutls_pubkey_export_dsa_raw2, "gnutls_pubkey_export_dsa_raw2");
            lib.bindSymbol_stdcall(gnutls_pubkey_export_ecc_raw2, "gnutls_pubkey_export_ecc_raw2");
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_pubkey_export_gost_raw2, "gnutls_pubkey_export_gost_raw2");

        lib.bindSymbol_stdcall(gnutls_pubkey_export_ecc_raw, "gnutls_pubkey_export_ecc_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_export_ecc_x962, "gnutls_pubkey_export_ecc_x962");
        lib.bindSymbol_stdcall(gnutls_pubkey_export, "gnutls_pubkey_export");
        lib.bindSymbol_stdcall(gnutls_pubkey_export2, "gnutls_pubkey_export2");
        lib.bindSymbol_stdcall(gnutls_pubkey_get_key_id, "gnutls_pubkey_get_key_id");
        lib.bindSymbol_stdcall(gnutls_pubkey_get_openpgp_key_id, "gnutls_pubkey_get_openpgp_key_id");
        lib.bindSymbol_stdcall(gnutls_pubkey_get_key_usage, "gnutls_pubkey_get_key_usage");
        lib.bindSymbol_stdcall(gnutls_pubkey_set_key_usage, "gnutls_pubkey_set_key_usage");
        lib.bindSymbol_stdcall(gnutls_pubkey_import, "gnutls_pubkey_import");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_dsa_raw, "gnutls_pubkey_import_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_rsa_raw, "gnutls_pubkey_import_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_ecc_x962, "gnutls_pubkey_import_ecc_x962");
        lib.bindSymbol_stdcall(gnutls_pubkey_import_ecc_raw, "gnutls_pubkey_import_ecc_raw");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_pubkey_import_gost_raw, "gnutls_pubkey_import_gost_raw");

        lib.bindSymbol_stdcall(gnutls_pubkey_encrypt_data, "gnutls_pubkey_encrypt_data");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_pubkey, "gnutls_x509_crt_set_pubkey");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_pubkey, "gnutls_x509_crq_set_pubkey");
        lib.bindSymbol_stdcall(gnutls_pubkey_verify_hash2, "gnutls_pubkey_verify_hash2");
        lib.bindSymbol_stdcall(gnutls_pubkey_verify_data2, "gnutls_pubkey_verify_data2");
        lib.bindSymbol_stdcall(gnutls_privkey_init, "gnutls_privkey_init");
        lib.bindSymbol_stdcall(gnutls_privkey_deinit, "gnutls_privkey_deinit");
        lib.bindSymbol_stdcall(gnutls_privkey_generate, "gnutls_privkey_generate");
        lib.bindSymbol_stdcall(gnutls_privkey_generate2, "gnutls_privkey_generate2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_privkey_set_spki, "gnutls_privkey_set_spki");
            lib.bindSymbol_stdcall(gnutls_privkey_get_spki, "gnutls_privkey_get_spki");
        }

        lib.bindSymbol_stdcall(gnutls_privkey_verify_seed, "gnutls_privkey_verify_seed");
        lib.bindSymbol_stdcall(gnutls_privkey_get_seed, "gnutls_privkey_get_seed");
        lib.bindSymbol_stdcall(gnutls_privkey_verify_params, "gnutls_privkey_verify_params");
        lib.bindSymbol_stdcall(gnutls_privkey_set_flags, "gnutls_privkey_set_flags");
        lib.bindSymbol_stdcall(gnutls_privkey_set_pin_function, "gnutls_privkey_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_privkey_get_pk_algorithm, "gnutls_privkey_get_pk_algorithm");
        lib.bindSymbol_stdcall(gnutls_privkey_get_type, "gnutls_privkey_get_type");
        lib.bindSymbol_stdcall(gnutls_privkey_status, "gnutls_privkey_status");
        lib.bindSymbol_stdcall(gnutls_privkey_import_pkcs11, "gnutls_privkey_import_pkcs11");
        lib.bindSymbol_stdcall(gnutls_privkey_import_x509, "gnutls_privkey_import_x509");
        lib.bindSymbol_stdcall(gnutls_privkey_import_openpgp, "gnutls_privkey_import_openpgp");
        lib.bindSymbol_stdcall(gnutls_privkey_export_x509, "gnutls_privkey_export_x509");
        lib.bindSymbol_stdcall(gnutls_privkey_export_openpgp, "gnutls_privkey_export_openpgp");
        lib.bindSymbol_stdcall(gnutls_privkey_export_pkcs11, "gnutls_privkey_export_pkcs11");
        lib.bindSymbol_stdcall(gnutls_privkey_import_openpgp_raw, "gnutls_privkey_import_openpgp_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_import_x509_raw, "gnutls_privkey_import_x509_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_import_tpm_raw, "gnutls_privkey_import_tpm_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_import_tpm_url, "gnutls_privkey_import_tpm_url");
        lib.bindSymbol_stdcall(gnutls_privkey_import_url, "gnutls_privkey_import_url");
        lib.bindSymbol_stdcall(gnutls_privkey_import_ext, "gnutls_privkey_import_ext");
        lib.bindSymbol_stdcall(gnutls_privkey_import_ext2, "gnutls_privkey_import_ext2");
        lib.bindSymbol_stdcall(gnutls_privkey_import_ext3, "gnutls_privkey_import_ext3");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            lib.bindSymbol_stdcall(gnutls_privkey_import_ext4, "gnutls_privkey_import_ext4");

        lib.bindSymbol_stdcall(gnutls_privkey_import_dsa_raw, "gnutls_privkey_import_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_import_rsa_raw, "gnutls_privkey_import_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_import_ecc_raw, "gnutls_privkey_import_ecc_raw");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_privkey_import_gost_raw, "gnutls_privkey_import_gost_raw");

        lib.bindSymbol_stdcall(gnutls_privkey_sign_data, "gnutls_privkey_sign_data");
        lib.bindSymbol_stdcall(gnutls_privkey_sign_data2, "gnutls_privkey_sign_data2");
        lib.bindSymbol_stdcall(gnutls_privkey_sign_hash, "gnutls_privkey_sign_hash");
        lib.bindSymbol_stdcall(gnutls_privkey_sign_hash2, "gnutls_privkey_sign_hash2");
        lib.bindSymbol_stdcall(gnutls_privkey_decrypt_data, "gnutls_privkey_decrypt_data");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            lib.bindSymbol_stdcall(gnutls_privkey_decrypt_data2, "gnutls_privkey_decrypt_data2");

        lib.bindSymbol_stdcall(gnutls_privkey_export_rsa_raw, "gnutls_privkey_export_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_export_dsa_raw, "gnutls_privkey_export_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_privkey_export_ecc_raw, "gnutls_privkey_export_ecc_raw");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_privkey_export_rsa_raw2, "gnutls_privkey_export_rsa_raw2");
            lib.bindSymbol_stdcall(gnutls_privkey_export_dsa_raw2, "gnutls_privkey_export_dsa_raw2");
            lib.bindSymbol_stdcall(gnutls_privkey_export_ecc_raw2, "gnutls_privkey_export_ecc_raw2");
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_privkey_export_gost_raw2, "gnutls_privkey_export_gost_raw2");

        lib.bindSymbol_stdcall(gnutls_x509_crt_privkey_sign, "gnutls_x509_crt_privkey_sign");
        lib.bindSymbol_stdcall(gnutls_x509_crl_privkey_sign, "gnutls_x509_crl_privkey_sign");
        lib.bindSymbol_stdcall(gnutls_x509_crq_privkey_sign, "gnutls_x509_crq_privkey_sign");
        lib.bindSymbol_stdcall(gnutls_pcert_import_x509, "gnutls_pcert_import_x509");
        lib.bindSymbol_stdcall(gnutls_pcert_import_x509_list, "gnutls_pcert_import_x509_list");
        lib.bindSymbol_stdcall(gnutls_pcert_export_x509, "gnutls_pcert_export_x509");
        lib.bindSymbol_stdcall(gnutls_pcert_list_import_x509_raw, "gnutls_pcert_list_import_x509_raw");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_pcert_list_import_x509_file, "gnutls_pcert_list_import_x509_file");

        lib.bindSymbol_stdcall(gnutls_pcert_import_x509_raw, "gnutls_pcert_import_x509_raw");
        lib.bindSymbol_stdcall(gnutls_pcert_import_openpgp_raw, "gnutls_pcert_import_openpgp_raw");
        lib.bindSymbol_stdcall(gnutls_pcert_import_openpgp, "gnutls_pcert_import_openpgp");
        lib.bindSymbol_stdcall(gnutls_pcert_export_openpgp, "gnutls_pcert_export_openpgp");
        lib.bindSymbol_stdcall(gnutls_pcert_deinit, "gnutls_pcert_deinit");
        lib.bindSymbol_stdcall(gnutls_pcert_import_rawpk, "gnutls_pcert_import_rawpk");
        lib.bindSymbol_stdcall(gnutls_pcert_import_rawpk_raw, "gnutls_pcert_import_rawpk_raw");
        lib.bindSymbol_stdcall(gnutls_certificate_set_retrieve_function2, "gnutls_certificate_set_retrieve_function2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_certificate_set_retrieve_function3, "gnutls_certificate_set_retrieve_function3");

        lib.bindSymbol_stdcall(gnutls_certificate_set_key, "gnutls_certificate_set_key");
        lib.bindSymbol_stdcall(gnutls_pubkey_print, "gnutls_pubkey_print");
    }
}
