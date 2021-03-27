module bindbc.gnutls.x509;

import bindbc.gnutls.config;
import bindbc.gnutls.gnutls;

import core.stdc.config;
import core.sys.posix.sys.select;

enum GNUTLS_OID_X520_COUNTRY_NAME = "2.5.4.6";
enum GNUTLS_OID_X520_ORGANIZATION_NAME = "2.5.4.10";
enum GNUTLS_OID_X520_ORGANIZATIONAL_UNIT_NAME = "2.5.4.11";
enum GNUTLS_OID_X520_COMMON_NAME = "2.5.4.3";
enum GNUTLS_OID_X520_LOCALITY_NAME = "2.5.4.7";
enum GNUTLS_OID_X520_STATE_OR_PROVINCE_NAME = "2.5.4.8";

enum GNUTLS_OID_X520_INITIALS = "2.5.4.43";
enum GNUTLS_OID_X520_GENERATION_QUALIFIER = "2.5.4.44";
enum GNUTLS_OID_X520_SURNAME = "2.5.4.4";
enum GNUTLS_OID_X520_GIVEN_NAME = "2.5.4.42";
enum GNUTLS_OID_X520_TITLE = "2.5.4.12";
enum GNUTLS_OID_X520_DN_QUALIFIER = "2.5.4.46";
enum GNUTLS_OID_X520_PSEUDONYM = "2.5.4.65";
enum GNUTLS_OID_X520_POSTALCODE = "2.5.4.17";
enum GNUTLS_OID_X520_NAME = "2.5.4.41";

enum GNUTLS_OID_LDAP_DC = "0.9.2342.19200300.100.1.25";
enum GNUTLS_OID_LDAP_UID = "0.9.2342.19200300.100.1.1";

enum GNUTLS_OID_PKCS9_EMAIL = "1.2.840.113549.1.9.1";

enum GNUTLS_OID_PKIX_DATE_OF_BIRTH = "1.3.6.1.5.5.7.9.1";
enum GNUTLS_OID_PKIX_PLACE_OF_BIRTH = "1.3.6.1.5.5.7.9.2";
enum GNUTLS_OID_PKIX_GENDER = "1.3.6.1.5.5.7.9.3";
enum GNUTLS_OID_PKIX_COUNTRY_OF_CITIZENSHIP = "1.3.6.1.5.5.7.9.4";
enum GNUTLS_OID_PKIX_COUNTRY_OF_RESIDENCE = "1.3.6.1.5.5.7.9.5";

enum GNUTLS_KP_TLS_WWW_SERVER = "1.3.6.1.5.5.7.3.1";
enum GNUTLS_KP_TLS_WWW_CLIENT = "1.3.6.1.5.5.7.3.2";
enum GNUTLS_KP_CODE_SIGNING = "1.3.6.1.5.5.7.3.3";
enum GNUTLS_KP_MS_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2";
enum GNUTLS_KP_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
enum GNUTLS_KP_TIME_STAMPING = "1.3.6.1.5.5.7.3.8";
enum GNUTLS_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
enum GNUTLS_KP_IPSEC_IKE = "1.3.6.1.5.5.7.3.17";
enum GNUTLS_KP_ANY = "2.5.29.37.0";

enum GNUTLS_KP_FLAG_DISALLOW_ANY = 1;

enum GNUTLS_OID_AIA = "1.3.6.1.5.5.7.1.1";
enum GNUTLS_OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";
enum GNUTLS_OID_AD_CAISSUERS = "1.3.6.1.5.5.7.48.2";

enum GNUTLS_FSAN_SET = 0;
enum GNUTLS_FSAN_APPEND = 1;
enum GNUTLS_FSAN_ENCODE_OCTET_STRING = 1 << 1;
enum GNUTLS_FSAN_ENCODE_UTF8_STRING = 1 << 2;

enum GNUTLS_X509EXT_OID_SUBJECT_KEY_ID = "2.5.29.14";
enum GNUTLS_X509EXT_OID_KEY_USAGE = "2.5.29.15";
enum GNUTLS_X509EXT_OID_PRIVATE_KEY_USAGE_PERIOD = "2.5.29.16";
enum GNUTLS_X509EXT_OID_SAN = "2.5.29.17";
enum GNUTLS_X509EXT_OID_IAN = "2.5.29.18";
enum GNUTLS_X509EXT_OID_BASIC_CONSTRAINTS = "2.5.29.19";
enum GNUTLS_X509EXT_OID_NAME_CONSTRAINTS = "2.5.29.30";
enum GNUTLS_X509EXT_OID_CRL_DIST_POINTS = "2.5.29.31";
enum GNUTLS_X509EXT_OID_CRT_POLICY = "2.5.29.32";
enum GNUTLS_X509EXT_OID_AUTHORITY_KEY_ID = "2.5.29.35";
enum GNUTLS_X509EXT_OID_EXTENDED_KEY_USAGE = "2.5.29.37";
enum GNUTLS_X509EXT_OID_INHIBIT_ANYPOLICY = "2.5.29.52";
enum GNUTLS_X509EXT_OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";
enum GNUTLS_X509EXT_OID_PROXY_CRT_INFO = "1.3.6.1.5.5.7.1.14";
enum GNUTLS_X509EXT_OID_TLSFEATURES = "1.3.6.1.5.5.7.1.24";

enum GNUTLS_X509_OID_POLICY_ANY = "2.5.29.54";

enum gnutls_certificate_import_flags
{
    GNUTLS_X509_CRT_LIST_IMPORT_FAIL_IF_EXCEED = 1,
    GNUTLS_X509_CRT_LIST_FAIL_IF_UNSORTED = 1 << 1,
    GNUTLS_X509_CRT_LIST_SORT = 1 << 2
}

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
{
    enum gnutls_x509_crt_flags
    {
        GNUTLS_X509_CRT_FLAG_IGNORE_SANITY = 1
    }
}

enum gnutls_keyid_flags_t
{
    GNUTLS_KEYID_USE_SHA1 = 0,
    GNUTLS_KEYID_USE_SHA256 = 1 << 0,
    GNUTLS_KEYID_USE_SHA512 = 1 << 1,
    GNUTLS_KEYID_USE_BEST_KNOWN = 1 << 30
}

enum gnutls_info_access_what_t
{
    GNUTLS_IA_ACCESSMETHOD_OID = 1,
    GNUTLS_IA_ACCESSLOCATION_GENERALNAME_TYPE = 2,

    GNUTLS_IA_URI = 106,

    GNUTLS_IA_UNKNOWN = 10000,
    GNUTLS_IA_OCSP_URI = 10006,
    GNUTLS_IA_CAISSUERS_URI = 10106
}

struct gnutls_name_constraints_st;
alias gnutls_x509_name_constraints_t = gnutls_name_constraints_st*;

enum GNUTLS_EXT_FLAG_APPEND = 1;

enum GNUTLS_NAME_CONSTRAINTS_FLAG_APPEND = GNUTLS_EXT_FLAG_APPEND;

enum gnutls_x509_crl_reason_flags_t
{
    GNUTLS_CRL_REASON_UNSPECIFIED = 0,
    GNUTLS_CRL_REASON_PRIVILEGE_WITHDRAWN = 1,
    GNUTLS_CRL_REASON_CERTIFICATE_HOLD = 2,
    GNUTLS_CRL_REASON_CESSATION_OF_OPERATION = 4,
    GNUTLS_CRL_REASON_SUPERSEDED = 8,
    GNUTLS_CRL_REASON_AFFILIATION_CHANGED = 16,
    GNUTLS_CRL_REASON_CA_COMPROMISE = 32,
    GNUTLS_CRL_REASON_KEY_COMPROMISE = 64,
    GNUTLS_CRL_REASON_UNUSED = 128,
    GNUTLS_CRL_REASON_AA_COMPROMISE = 32768
}

enum GNUTLS_X509_NO_WELL_DEFINED_EXPIRATION = cast(time_t) 4294197631;

struct gnutls_x509_spki_st;
alias gnutls_x509_spki_t = gnutls_x509_spki_st*;

struct gnutls_x509_tlsfeatures_st;
alias gnutls_x509_tlsfeatures_t = gnutls_x509_tlsfeatures_st*;

enum GNUTLS_MAX_QUALIFIERS = 8;

enum gnutls_x509_qualifier_t
{
    GNUTLS_X509_QUALIFIER_UNKNOWN = 0,
    GNUTLS_X509_QUALIFIER_URI = 1,
    GNUTLS_X509_QUALIFIER_NOTICE = 2
}

struct gnutls_x509_policy_st
{
    char* oid;
    uint qualifiers;

    struct _Anonymous_0
    {
        gnutls_x509_qualifier_t type;
        char* data;
        uint size;
    }

    _Anonymous_0[GNUTLS_MAX_QUALIFIERS] qualifier;
}

enum GNUTLS_X509_DN_OID_RETURN_OID = 1;

struct gnutls_x509_dn_st;
alias gnutls_x509_dn_t = gnutls_x509_dn_st*;

struct gnutls_x509_ava_st
{
    gnutls_datum_t oid;
    gnutls_datum_t value;
    c_ulong value_tag;
}

enum GNUTLS_X509_DN_FLAG_COMPAT = 1;

struct gnutls_x509_crl_iter;
alias gnutls_x509_crl_iter_t = gnutls_x509_crl_iter*;

enum gnutls_certificate_verify_flags
{
    GNUTLS_VERIFY_DISABLE_CA_SIGN = 1 << 0,
    GNUTLS_VERIFY_DO_NOT_ALLOW_IP_MATCHES = 1 << 1, /// Available from GnuTLS 3.6.0
    GNUTLS_VERIFY_DO_NOT_ALLOW_SAME = 1 << 2,
    GNUTLS_VERIFY_ALLOW_ANY_X509_V1_CA_CRT = 1 << 3,
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 = 1 << 4,
    GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5 = 1 << 5,
    GNUTLS_VERIFY_DISABLE_TIME_CHECKS = 1 << 6,
    GNUTLS_VERIFY_DISABLE_TRUSTED_TIME_CHECKS = 1 << 7,
    GNUTLS_VERIFY_DO_NOT_ALLOW_X509_V1_CA_CRT = 1 << 8,
    GNUTLS_VERIFY_DISABLE_CRL_CHECKS = 1 << 9,
    GNUTLS_VERIFY_ALLOW_UNSORTED_CHAIN = 1 << 10,
    GNUTLS_VERIFY_DO_NOT_ALLOW_UNSORTED_CHAIN = 1 << 11,
    GNUTLS_VERIFY_DO_NOT_ALLOW_WILDCARDS = 1 << 12,
    GNUTLS_VERIFY_USE_TLS1_RSA = 1 << 13,
    GNUTLS_VERIFY_IGNORE_UNKNOWN_CRIT_EXTENSIONS = 1 << 14, /// Available from GnuTLS 3.6.0
    GNUTLS_VERIFY_ALLOW_SIGN_WITH_SHA1 = 1 << 15 /// Available from GnuTLS 3.6.0
}

enum GNUTLS_VERIFY_ALLOW_BROKEN = gnutls_certificate_verify_flags.GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD2 | gnutls_certificate_verify_flags.GNUTLS_VERIFY_ALLOW_SIGN_RSA_MD5;

enum gnutls_certificate_verification_profiles_t
{
    GNUTLS_PROFILE_UNKNOWN = 0,
    GNUTLS_PROFILE_VERY_WEAK = 1,
    GNUTLS_PROFILE_LOW = 2,
    GNUTLS_PROFILE_LEGACY = 4,
    GNUTLS_PROFILE_MEDIUM = 5,
    GNUTLS_PROFILE_HIGH = 6,
    GNUTLS_PROFILE_ULTRA = 7,
    GNUTLS_PROFILE_FUTURE = 8,

    GNUTLS_PROFILE_SUITEB128 = 32,
    GNUTLS_PROFILE_SUITEB192 = 33
}

enum GNUTLS_VFLAGS_PROFILE_MASK = 0xff000000;

enum GNUTLS_PKCS8_PLAIN = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PLAIN;
enum GNUTLS_PKCS8_USE_PKCS12_3DES = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_3DES;
enum GNUTLS_PKCS8_USE_PKCS12_ARCFOUR = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_ARCFOUR;
enum GNUTLS_PKCS8_USE_PKCS12_RC2_40 = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_RC2_40;

enum gnutls_pkcs_encrypt_flags_t
{
    GNUTLS_PKCS_PLAIN = 1,
    GNUTLS_PKCS_PKCS12_3DES = 1 << 1,
    GNUTLS_PKCS_PKCS12_ARCFOUR = 1 << 2,
    GNUTLS_PKCS_PKCS12_RC2_40 = 1 << 3,
    GNUTLS_PKCS_PBES2_3DES = 1 << 4,
    GNUTLS_PKCS_PBES2_AES_128 = 1 << 5,
    GNUTLS_PKCS_PBES2_AES_192 = 1 << 6,
    GNUTLS_PKCS_PBES2_AES_256 = 1 << 7,
    GNUTLS_PKCS_NULL_PASSWORD = 1 << 8,
    GNUTLS_PKCS_PBES2_DES = 1 << 9,
    GNUTLS_PKCS_PBES1_DES_MD5 = 1 << 10,
    GNUTLS_PKCS_PBES2_GOST_TC26Z = 1 << 11,
    GNUTLS_PKCS_PBES2_GOST_CPA = 1 << 12,
    GNUTLS_PKCS_PBES2_GOST_CPB = 1 << 13,
    GNUTLS_PKCS_PBES2_GOST_CPC = 1 << 14,
    GNUTLS_PKCS_PBES2_GOST_CPD = 1 << 15
}

enum GNUTLS_PKCS_USE_PKCS12_3DES = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_3DES;
enum GNUTLS_PKCS_USE_PKCS12_ARCFOUR = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_ARCFOUR;
enum GNUTLS_PKCS_USE_PKCS12_RC2_40 = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PKCS12_RC2_40;
enum GNUTLS_PKCS_USE_PBES2_3DES = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_3DES;
enum GNUTLS_PKCS_USE_PBES2_AES_128 = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_AES_128;
enum GNUTLS_PKCS_USE_PBES2_AES_192 = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_AES_192;
enum GNUTLS_PKCS_USE_PBES2_AES_256 = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_AES_256;
enum GNUTLS_PKCS_USE_PBES2_GOST_TC26Z = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_GOST_TC26Z;
enum GNUTLS_PKCS_USE_PBES2_GOST_CPA = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_GOST_CPA;
enum GNUTLS_PKCS_USE_PBES2_GOST_CPB = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_GOST_CPB;
enum GNUTLS_PKCS_USE_PBES2_GOST_CPC = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_GOST_CPC;
enum GNUTLS_PKCS_USE_PBES2_GOST_CPD = gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_PBES2_GOST_CPD;

enum gnutls_keygen_types_t
{
    GNUTLS_KEYGEN_SEED = 1,
    GNUTLS_KEYGEN_DIGEST = 2,
    GNUTLS_KEYGEN_SPKI = 3
}

struct gnutls_keygen_data_st
{
    gnutls_keygen_types_t type;
    ubyte* data;
    uint size;
}

struct gnutls_x509_trust_list_st;
alias gnutls_x509_trust_list_t = gnutls_x509_trust_list_st*;
struct gnutls_x509_trust_list_iter;
alias gnutls_x509_trust_list_iter_t = gnutls_x509_trust_list_iter*;

enum gnutls_trust_list_flags_t
{
    GNUTLS_TL_VERIFY_CRL = 1,

    GNUTLS_TL_USE_IN_TLS = 1 << 1,

    GNUTLS_TL_NO_DUPLICATES = 1 << 2,

    GNUTLS_TL_NO_DUPLICATE_KEY = 1 << 3,

    GNUTLS_TL_GET_COPY = 1 << 4,

    GNUTLS_TL_FAIL_ON_INVALID_CRL = 1 << 5
}

enum GNUTLS_TL_VERIFY_CRL = 1;
enum GNUTLS_TL_USE_IN_TLS = 1 << 1;
enum GNUTLS_TL_NO_DUPLICATES = 1 << 2;
enum GNUTLS_TL_NO_DUPLICATE_KEY = 1 << 3;
enum GNUTLS_TL_GET_COPY = 1 << 4;
enum GNUTLS_TL_FAIL_ON_INVALID_CRL = 1 << 5;

struct gnutls_x509_ext_st
{
    char* oid;
    uint critical;
    gnutls_datum_t data;
}

alias gnutls_x509_crl_get_certificate_count = gnutls_x509_crl_get_crt_count;
alias gnutls_x509_crl_get_certificate = gnutls_x509_crl_get_crt_serial;

extern(C) nothrow @nogc
{
    alias gnutls_verify_output_function = int function (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer, gnutls_x509_crl_t crl, uint verification_output);
}

extern (D) nothrow @nogc @safe pure
{
    uint GNUTLS_PROFILE_TO_VFLAGS(uint x)
    {
        return (cast(uint) x) << 24;
    }

    uint GNUTLS_VFLAGS_TO_PROFILE(uint x)
    {
        return ((cast(uint) x) >> 24) & 0xff;
    }

    uint GNUTLS_PKCS_CIPHER_MASK(uint x)
    {
        return x & (~gnutls_pkcs_encrypt_flags_t.GNUTLS_PKCS_NULL_PASSWORD);
    }
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_x509_crt_init (gnutls_x509_crt_t* cert);
    void gnutls_x509_crt_deinit (gnutls_x509_crt_t cert);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        void gnutls_x509_crt_set_flags (gnutls_x509_crt_t cert, uint flags);

    uint gnutls_x509_crt_equals (gnutls_x509_crt_t cert1, gnutls_x509_crt_t cert2);
    uint gnutls_x509_crt_equals2 (gnutls_x509_crt_t cert1, const(gnutls_datum_t)* der);
    int gnutls_x509_crt_import (gnutls_x509_crt_t cert, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_x509_crt_list_import2 (gnutls_x509_crt_t** certs, uint* size, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_x509_crt_list_import (gnutls_x509_crt_t* certs, uint* cert_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_x509_crt_import_url (gnutls_x509_crt_t crt, const(char)* url, uint flags);
    int gnutls_x509_crt_list_import_url (gnutls_x509_crt_t** certs, uint* size, const(char)* url, gnutls_pin_callback_t pin_fn, void* pin_fn_userdata, uint flags);
    int gnutls_x509_crt_export (gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_x509_crt_export2 (gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_x509_crt_get_private_key_usage_period (gnutls_x509_crt_t cert, time_t* activation, time_t* expiration, uint* critical);
    int gnutls_x509_crt_get_issuer_dn (gnutls_x509_crt_t cert, char* buf, size_t* buf_size);
    int gnutls_x509_crt_get_issuer_dn2 (gnutls_x509_crt_t cert, gnutls_datum_t* dn);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_crt_get_issuer_dn3 (gnutls_x509_crt_t cert, gnutls_datum_t* dn, uint flags);

    int gnutls_x509_crt_get_issuer_dn_oid (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
    int gnutls_x509_crt_get_issuer_dn_by_oid (gnutls_x509_crt_t cert, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* buf_size);
    int gnutls_x509_crt_get_dn (gnutls_x509_crt_t cert, char* buf, size_t* buf_size);
    int gnutls_x509_crt_get_dn2 (gnutls_x509_crt_t cert, gnutls_datum_t* dn);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_crt_get_dn3 (gnutls_x509_crt_t cert, gnutls_datum_t* dn, uint flags);

    int gnutls_x509_crt_get_dn_oid (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
    int gnutls_x509_crt_get_dn_by_oid (gnutls_x509_crt_t cert, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* buf_size);
    uint gnutls_x509_crt_check_hostname (gnutls_x509_crt_t cert, const(char)* hostname);
    uint gnutls_x509_crt_check_hostname2 (gnutls_x509_crt_t cert, const(char)* hostname, uint flags);
    uint gnutls_x509_crt_check_email (gnutls_x509_crt_t cert, const(char)* email, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        uint gnutls_x509_crt_check_ip (gnutls_x509_crt_t cert, const(ubyte)* ip, uint ip_size, uint flags);

    int gnutls_x509_crt_get_signature_algorithm (gnutls_x509_crt_t cert);
    int gnutls_x509_crt_get_signature (gnutls_x509_crt_t cert, char* sig, size_t* sizeof_sig);
    int gnutls_x509_crt_get_version (gnutls_x509_crt_t cert);
    int gnutls_x509_crt_get_pk_oid (gnutls_x509_crt_t cert, char* oid, size_t* oid_size);
    int gnutls_x509_crt_get_signature_oid (gnutls_x509_crt_t cert, char* oid, size_t* oid_size);
    int gnutls_x509_crt_get_key_id (gnutls_x509_crt_t crt, uint flags, ubyte* output_data, size_t* output_data_size);
    int gnutls_x509_crt_set_private_key_usage_period (gnutls_x509_crt_t crt, time_t activation, time_t expiration);
    int gnutls_x509_crt_set_authority_key_id (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
    int gnutls_x509_crt_get_authority_key_id (gnutls_x509_crt_t cert, void* id, size_t* id_size, uint* critical);
    int gnutls_x509_crt_get_authority_key_gn_serial (gnutls_x509_crt_t cert, uint seq, void* alt, size_t* alt_size, uint* alt_type, void* serial, size_t* serial_size, uint* critical);
    int gnutls_x509_crt_get_subject_key_id (gnutls_x509_crt_t cert, void* ret, size_t* ret_size, uint* critical);
    int gnutls_x509_crt_get_subject_unique_id (gnutls_x509_crt_t crt, char* buf, size_t* buf_size);
    int gnutls_x509_crt_get_issuer_unique_id (gnutls_x509_crt_t crt, char* buf, size_t* buf_size);
    void gnutls_x509_crt_set_pin_function (gnutls_x509_crt_t crt, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_x509_crt_get_authority_info_access (gnutls_x509_crt_t crt, uint seq, int what, gnutls_datum_t* data, uint* critical);
    uint gnutls_x509_name_constraints_check (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
    uint gnutls_x509_name_constraints_check_crt (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, gnutls_x509_crt_t crt);
    int gnutls_x509_name_constraints_init (gnutls_x509_name_constraints_t* nc);
    void gnutls_x509_name_constraints_deinit (gnutls_x509_name_constraints_t nc);
    int gnutls_x509_crt_get_name_constraints (gnutls_x509_crt_t crt, gnutls_x509_name_constraints_t nc, uint flags, uint* critical);
    int gnutls_x509_name_constraints_add_permitted (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
    int gnutls_x509_name_constraints_add_excluded (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
    int gnutls_x509_crt_set_name_constraints (gnutls_x509_crt_t crt, gnutls_x509_name_constraints_t nc, uint critical);
    int gnutls_x509_name_constraints_get_permitted (gnutls_x509_name_constraints_t nc, uint idx, uint* type, gnutls_datum_t* name);
    int gnutls_x509_name_constraints_get_excluded (gnutls_x509_name_constraints_t nc, uint idx, uint* type, gnutls_datum_t* name);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
        int gnutls_x509_cidr_to_rfc5280 (const(char)* cidr, gnutls_datum_t* cidr_rfc5280);

    int gnutls_x509_crt_get_crl_dist_points (gnutls_x509_crt_t cert, uint seq, void* ret, size_t* ret_size, uint* reason_flags, uint* critical);
    int gnutls_x509_crt_set_crl_dist_points2 (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint reason_flags);
    int gnutls_x509_crt_set_crl_dist_points (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data_string, uint reason_flags);
    int gnutls_x509_crt_cpy_crl_dist_points (gnutls_x509_crt_t dst, gnutls_x509_crt_t src);
    int gnutls_x509_crl_sign (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key);
    int gnutls_x509_crl_sign2 (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
    time_t gnutls_x509_crt_get_activation_time (gnutls_x509_crt_t cert);
    time_t gnutls_x509_crt_get_expiration_time (gnutls_x509_crt_t cert);
    int gnutls_x509_crt_get_serial (gnutls_x509_crt_t cert, void* result, size_t* result_size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_x509_spki_init (gnutls_x509_spki_t* spki);
        void gnutls_x509_spki_deinit (gnutls_x509_spki_t spki);
    }

    int gnutls_x509_spki_get_rsa_pss_params (gnutls_x509_spki_t spki, gnutls_digest_algorithm_t* dig, uint* salt_size);
    void gnutls_x509_spki_set_rsa_pss_params (gnutls_x509_spki_t spki, gnutls_digest_algorithm_t dig, uint salt_size);
    int gnutls_x509_crt_get_pk_algorithm (gnutls_x509_crt_t cert, uint* bits);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_x509_crt_set_spki (gnutls_x509_crt_t crt, const gnutls_x509_spki_t spki, uint flags);
        int gnutls_x509_crt_get_spki (gnutls_x509_crt_t cert, gnutls_x509_spki_t spki, uint flags);
    }

    int gnutls_x509_crt_get_pk_rsa_raw (gnutls_x509_crt_t crt, gnutls_datum_t* m, gnutls_datum_t* e);
    int gnutls_x509_crt_get_pk_dsa_raw (gnutls_x509_crt_t crt, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);
    int gnutls_x509_crt_get_pk_ecc_raw (gnutls_x509_crt_t crt, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y);
    int gnutls_x509_crt_get_pk_gost_raw (gnutls_x509_crt_t crt, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y);
    int gnutls_x509_crt_get_subject_alt_name (gnutls_x509_crt_t cert, uint seq, void* san, size_t* san_size, uint* critical);
    int gnutls_x509_crt_get_subject_alt_name2 (gnutls_x509_crt_t cert, uint seq, void* san, size_t* san_size, uint* san_type, uint* critical);
    int gnutls_x509_crt_get_subject_alt_othername_oid (gnutls_x509_crt_t cert, uint seq, void* oid, size_t* oid_size);
    int gnutls_x509_crt_get_issuer_alt_name (gnutls_x509_crt_t cert, uint seq, void* ian, size_t* ian_size, uint* critical);
    int gnutls_x509_crt_get_issuer_alt_name2 (gnutls_x509_crt_t cert, uint seq, void* ian, size_t* ian_size, uint* ian_type, uint* critical);
    int gnutls_x509_crt_get_issuer_alt_othername_oid (gnutls_x509_crt_t cert, uint seq, void* ret, size_t* ret_size);
    int gnutls_x509_crt_get_ca_status (gnutls_x509_crt_t cert, uint* critical);
    int gnutls_x509_crt_get_basic_constraints (gnutls_x509_crt_t cert, uint* critical, uint* ca, int* pathlen);
    int gnutls_x509_crt_get_key_usage (gnutls_x509_crt_t cert, uint* key_usage, uint* critical);
    int gnutls_x509_crt_set_key_usage (gnutls_x509_crt_t crt, uint usage);
    int gnutls_x509_crt_set_authority_info_access (gnutls_x509_crt_t crt, int what, gnutls_datum_t* data);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_x509_crt_get_inhibit_anypolicy (gnutls_x509_crt_t cert, uint* skipcerts, uint* critical);
        int gnutls_x509_crt_set_inhibit_anypolicy (gnutls_x509_crt_t crt, uint skipcerts);
    }

    int gnutls_x509_crt_get_proxy (gnutls_x509_crt_t cert, uint* critical, int* pathlen, char** policyLanguage, char** policy, size_t* sizeof_policy);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
    {
        int gnutls_x509_tlsfeatures_init (gnutls_x509_tlsfeatures_t* features);
        void gnutls_x509_tlsfeatures_deinit (gnutls_x509_tlsfeatures_t);
        int gnutls_x509_tlsfeatures_get (gnutls_x509_tlsfeatures_t f, uint idx, uint* feature);
        int gnutls_x509_crt_set_tlsfeatures (gnutls_x509_crt_t crt, gnutls_x509_tlsfeatures_t features);
        int gnutls_x509_crt_get_tlsfeatures (gnutls_x509_crt_t cert, gnutls_x509_tlsfeatures_t features, uint flags, uint* critical);
    }

    uint gnutls_x509_tlsfeatures_check_crt (gnutls_x509_tlsfeatures_t feat, gnutls_x509_crt_t crt);
    void gnutls_x509_policy_release (gnutls_x509_policy_st* policy);
    int gnutls_x509_crt_get_policy (gnutls_x509_crt_t crt, uint indx, gnutls_x509_policy_st* policy, uint* critical);
    int gnutls_x509_crt_set_policy (gnutls_x509_crt_t crt, const(gnutls_x509_policy_st)* policy, uint critical);
    int gnutls_x509_dn_oid_known (const(char)* oid);
    const(char)* gnutls_x509_dn_oid_name (const(char)* oid, uint flags);
    int gnutls_x509_crt_get_extension_oid (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
    int gnutls_x509_crt_get_extension_by_oid (gnutls_x509_crt_t cert, const(char)* oid, uint indx, void* buf, size_t* buf_size, uint* critical);
    int gnutls_x509_crq_get_signature_algorithm (gnutls_x509_crq_t crq);
    int gnutls_x509_crq_get_extension_by_oid2 (gnutls_x509_crq_t crq, const(char)* oid, uint indx, gnutls_datum_t* output, uint* critical);
    int gnutls_x509_crt_get_extension_info (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size, uint* critical);
    int gnutls_x509_crt_get_extension_data (gnutls_x509_crt_t cert, uint indx, void* data, size_t* sizeof_data);
    int gnutls_x509_crt_get_extension_data2 (gnutls_x509_crt_t cert, uint indx, gnutls_datum_t* data);
    int gnutls_x509_crt_set_extension_by_oid (gnutls_x509_crt_t crt, const(char)* oid, const(void)* buf, size_t sizeof_buf, uint critical);
    int gnutls_x509_crt_set_dn (gnutls_x509_crt_t crt, const(char)* dn, const(char*)* err);
    int gnutls_x509_crt_set_dn_by_oid (gnutls_x509_crt_t crt, const(char)* oid, uint raw_flag, const(void)* name, uint sizeof_name);
    int gnutls_x509_crt_set_issuer_dn_by_oid (gnutls_x509_crt_t crt, const(char)* oid, uint raw_flag, const(void)* name, uint sizeof_name);
    int gnutls_x509_crt_set_issuer_dn (gnutls_x509_crt_t crt, const(char)* dn, const(char*)* err);
    int gnutls_x509_crt_set_version (gnutls_x509_crt_t crt, uint version_);
    int gnutls_x509_crt_set_key (gnutls_x509_crt_t crt, gnutls_x509_privkey_t key);
    int gnutls_x509_crt_set_ca_status (gnutls_x509_crt_t crt, uint ca);
    int gnutls_x509_crt_set_basic_constraints (gnutls_x509_crt_t crt, uint ca, int pathLenConstraint);
    int gnutls_x509_crt_set_subject_unique_id (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
    int gnutls_x509_crt_set_issuer_unique_id (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
    int gnutls_x509_crt_set_subject_alternative_name (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(char)* data_string);
    int gnutls_x509_crt_set_subject_alt_name (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crt_set_subject_alt_othername (gnutls_x509_crt_t crt, const(char)* oid, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crt_set_issuer_alt_name (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crt_set_issuer_alt_othername (gnutls_x509_crt_t crt, const(char)* oid, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crt_sign (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key);
    int gnutls_x509_crt_sign2 (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_x509_crt_set_activation_time (gnutls_x509_crt_t cert, time_t act_time);
    int gnutls_x509_crt_set_expiration_time (gnutls_x509_crt_t cert, time_t exp_time);
    int gnutls_x509_crt_set_serial (gnutls_x509_crt_t cert, const(void)* serial, size_t serial_size);
    int gnutls_x509_crt_set_subject_key_id (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
    int gnutls_x509_crt_set_proxy_dn (gnutls_x509_crt_t crt, gnutls_x509_crt_t eecrt, uint raw_flag, const(void)* name, uint sizeof_name);
    int gnutls_x509_crt_set_proxy (gnutls_x509_crt_t crt, int pathLenConstraint, const(char)* policyLanguage, const(char)* policy, size_t sizeof_policy);
    int gnutls_x509_crt_print (gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    int gnutls_x509_crl_print (gnutls_x509_crl_t crl, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    int gnutls_x509_crt_get_raw_issuer_dn (gnutls_x509_crt_t cert, gnutls_datum_t* start);
    int gnutls_x509_crt_get_raw_dn (gnutls_x509_crt_t cert, gnutls_datum_t* start);
    int gnutls_x509_rdn_get (const(gnutls_datum_t)* idn, char* buf, size_t* sizeof_buf);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_rdn_get2 (const(gnutls_datum_t)* idn, gnutls_datum_t* str, uint flags);

    int gnutls_x509_rdn_get_oid (const(gnutls_datum_t)* idn, uint indx, void* buf, size_t* sizeof_buf);
    int gnutls_x509_rdn_get_by_oid (const(gnutls_datum_t)* idn, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
    int gnutls_x509_crt_get_subject (gnutls_x509_crt_t cert, gnutls_x509_dn_t* dn);
    int gnutls_x509_crt_get_issuer (gnutls_x509_crt_t cert, gnutls_x509_dn_t* dn);
    int gnutls_x509_dn_get_rdn_ava (gnutls_x509_dn_t dn, int irdn, int iava, gnutls_x509_ava_st* ava);
    int gnutls_x509_dn_get_str (gnutls_x509_dn_t dn, gnutls_datum_t* str);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_dn_get_str2 (gnutls_x509_dn_t dn, gnutls_datum_t* str, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
        int gnutls_x509_dn_set_str (gnutls_x509_dn_t dn, const(char)* str, const(char*)* err);

    int gnutls_x509_dn_init (gnutls_x509_dn_t* dn);
    int gnutls_x509_dn_import (gnutls_x509_dn_t dn, const(gnutls_datum_t)* data);
    int gnutls_x509_dn_export (gnutls_x509_dn_t dn, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_x509_dn_export2 (gnutls_x509_dn_t dn, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    void gnutls_x509_dn_deinit (gnutls_x509_dn_t dn);
    int gnutls_x509_crl_init (gnutls_x509_crl_t* crl);
    void gnutls_x509_crl_deinit (gnutls_x509_crl_t crl);
    int gnutls_x509_crl_import (gnutls_x509_crl_t crl, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_x509_crl_export (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_x509_crl_export2 (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_x509_crl_get_raw_issuer_dn (gnutls_x509_crl_t crl, gnutls_datum_t* dn);
    int gnutls_x509_crl_get_issuer_dn (gnutls_x509_crl_t crl, char* buf, size_t* sizeof_buf);
    int gnutls_x509_crl_get_issuer_dn2 (gnutls_x509_crl_t crl, gnutls_datum_t* dn);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_crl_get_issuer_dn3 (gnutls_x509_crl_t crl, gnutls_datum_t* dn, uint flags);

    int gnutls_x509_crl_get_issuer_dn_by_oid (gnutls_x509_crl_t crl, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
    int gnutls_x509_crl_get_dn_oid (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid);
    int gnutls_x509_crl_get_signature_algorithm (gnutls_x509_crl_t crl);
    int gnutls_x509_crl_get_signature (gnutls_x509_crl_t crl, char* sig, size_t* sizeof_sig);
    int gnutls_x509_crl_get_version (gnutls_x509_crl_t crl);
    int gnutls_x509_crl_get_signature_oid (gnutls_x509_crl_t crl, char* oid, size_t* oid_size);
    time_t gnutls_x509_crl_get_this_update (gnutls_x509_crl_t crl);
    time_t gnutls_x509_crl_get_next_update (gnutls_x509_crl_t crl);
    int gnutls_x509_crl_get_crt_count (gnutls_x509_crl_t crl);
    int gnutls_x509_crl_get_crt_serial (gnutls_x509_crl_t crl, uint indx, ubyte* serial, size_t* serial_size, time_t* t);
    int gnutls_x509_crl_iter_crt_serial (gnutls_x509_crl_t crl, gnutls_x509_crl_iter_t*, ubyte* serial, size_t* serial_size, time_t* t);
    void gnutls_x509_crl_iter_deinit (gnutls_x509_crl_iter_t);
    uint gnutls_x509_crl_check_issuer (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer);
    int gnutls_x509_crl_list_import2 (gnutls_x509_crl_t** crls, uint* size, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_x509_crl_list_import (gnutls_x509_crl_t* crls, uint* crl_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
    int gnutls_x509_crl_set_version (gnutls_x509_crl_t crl, uint version_);
    int gnutls_x509_crl_set_this_update (gnutls_x509_crl_t crl, time_t act_time);
    int gnutls_x509_crl_set_next_update (gnutls_x509_crl_t crl, time_t exp_time);
    int gnutls_x509_crl_set_crt_serial (gnutls_x509_crl_t crl, const(void)* serial, size_t serial_size, time_t revocation_time);
    int gnutls_x509_crl_set_crt (gnutls_x509_crl_t crl, gnutls_x509_crt_t crt, time_t revocation_time);
    int gnutls_x509_crl_get_authority_key_id (gnutls_x509_crl_t crl, void* id, size_t* id_size, uint* critical);
    int gnutls_x509_crl_get_authority_key_gn_serial (gnutls_x509_crl_t crl, uint seq, void* alt, size_t* alt_size, uint* alt_type, void* serial, size_t* serial_size, uint* critical);
    int gnutls_x509_crl_get_number (gnutls_x509_crl_t crl, void* ret, size_t* ret_size, uint* critical);
    int gnutls_x509_crl_get_extension_oid (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid);
    int gnutls_x509_crl_get_extension_info (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
    int gnutls_x509_crl_get_extension_data (gnutls_x509_crl_t crl, uint indx, void* data, size_t* sizeof_data);
    int gnutls_x509_crl_get_extension_data2 (gnutls_x509_crl_t crl, uint indx, gnutls_datum_t* data);
    int gnutls_x509_crl_set_authority_key_id (gnutls_x509_crl_t crl, const(void)* id, size_t id_size);
    int gnutls_x509_crl_set_number (gnutls_x509_crl_t crl, const(void)* nr, size_t nr_size);
    const(char)* gnutls_certificate_verification_profile_get_name (gnutls_certificate_verification_profiles_t id);
    gnutls_certificate_verification_profiles_t gnutls_certificate_verification_profile_get_id (const(char)* name);
    uint gnutls_x509_crt_check_issuer (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer);
    int gnutls_x509_crt_list_verify (const(gnutls_x509_crt_t)* cert_list, uint cert_list_length, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, const(gnutls_x509_crl_t)* CRL_list, uint CRL_list_length, uint flags, uint* verify);
    int gnutls_x509_crt_verify (gnutls_x509_crt_t cert, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, uint flags, uint* verify);
    int gnutls_x509_crl_verify (gnutls_x509_crl_t crl, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, uint flags, uint* verify);
    int gnutls_x509_crt_verify_data2 (gnutls_x509_crt_t crt, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, const(gnutls_datum_t)* signature);
    int gnutls_x509_crt_check_revocation (gnutls_x509_crt_t cert, const(gnutls_x509_crl_t)* crl_list, uint crl_list_length);
    int gnutls_x509_crt_get_fingerprint (gnutls_x509_crt_t cert, gnutls_digest_algorithm_t algo, void* buf, size_t* buf_size);
    int gnutls_x509_crt_get_key_purpose_oid (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size, uint* critical);
    int gnutls_x509_crt_set_key_purpose_oid (gnutls_x509_crt_t cert, const(void)* oid, uint critical);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
        uint gnutls_x509_crt_check_key_purpose (gnutls_x509_crt_t cert, const(char)* purpose, uint flags);

    const(char)* gnutls_pkcs_schema_get_name (uint schema);
    const(char)* gnutls_pkcs_schema_get_oid (uint schema);
    int gnutls_x509_privkey_init (gnutls_x509_privkey_t* key);
    void gnutls_x509_privkey_deinit (gnutls_x509_privkey_t key);
    gnutls_sec_param_t gnutls_x509_privkey_sec_param (gnutls_x509_privkey_t key);
    void gnutls_x509_privkey_set_pin_function (gnutls_x509_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_x509_privkey_cpy (gnutls_x509_privkey_t dst, gnutls_x509_privkey_t src);
    int gnutls_x509_privkey_import (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_x509_privkey_import_pkcs8 (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);
    int gnutls_x509_privkey_import_openssl (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, const(char)* password);
    int gnutls_pkcs8_info (const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint* schema, uint* cipher, void* salt, uint* salt_size, uint* iter_count, char** oid);
    int gnutls_x509_privkey_import2 (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);
    int gnutls_x509_privkey_import_rsa_raw (gnutls_x509_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u);
    int gnutls_x509_privkey_import_rsa_raw2 (gnutls_x509_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u, const(gnutls_datum_t)* e1, const(gnutls_datum_t)* e2);
    int gnutls_x509_privkey_import_ecc_raw (gnutls_x509_privkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);
    int gnutls_x509_privkey_import_gost_raw (gnutls_x509_privkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);
    int gnutls_x509_privkey_fix (gnutls_x509_privkey_t key);
    int gnutls_x509_privkey_export_dsa_raw (gnutls_x509_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
    int gnutls_x509_privkey_import_dsa_raw (gnutls_x509_privkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y, const(gnutls_datum_t)* x);
    int gnutls_x509_privkey_get_pk_algorithm (gnutls_x509_privkey_t key);
    int gnutls_x509_privkey_get_pk_algorithm2 (gnutls_x509_privkey_t key, uint* bits);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_x509_privkey_get_spki (gnutls_x509_privkey_t key, gnutls_x509_spki_t spki, uint flags);
        int gnutls_x509_privkey_set_spki (gnutls_x509_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
    }

    int gnutls_x509_privkey_get_key_id (gnutls_x509_privkey_t key, uint flags, ubyte* output_data, size_t* output_data_size);
    int gnutls_x509_privkey_generate (gnutls_x509_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags);
    void gnutls_x509_privkey_set_flags (gnutls_x509_privkey_t key, uint flags);
    int gnutls_x509_privkey_generate2 (gnutls_x509_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags, const(gnutls_keygen_data_st)* data, uint data_size);
    int gnutls_x509_privkey_verify_seed (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t, const(void)* seed, size_t seed_size);
    int gnutls_x509_privkey_get_seed (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t*, void* seed, size_t* seed_size);
    int gnutls_x509_privkey_verify_params (gnutls_x509_privkey_t key);
    int gnutls_x509_privkey_export (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_x509_privkey_export2 (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_x509_privkey_export_pkcs8 (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags, void* output_data, size_t* output_data_size);
    int gnutls_x509_privkey_export2_pkcs8 (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags, gnutls_datum_t* out_);
    int gnutls_x509_privkey_export_rsa_raw2 (gnutls_x509_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2);
    int gnutls_x509_privkey_export_rsa_raw (gnutls_x509_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u);
    int gnutls_x509_privkey_export_ecc_raw (gnutls_x509_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);
    int gnutls_x509_privkey_export_gost_raw (gnutls_x509_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);
    int gnutls_x509_privkey_sign_data (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t digest, uint flags, const(gnutls_datum_t)* data, void* signature, size_t* signature_size);
    int gnutls_x509_crq_sign (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key);
    int gnutls_x509_crq_sign2 (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key, gnutls_digest_algorithm_t dig, uint flags);
    int gnutls_x509_crq_print (gnutls_x509_crq_t crq, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    int gnutls_x509_crq_verify (gnutls_x509_crq_t crq, uint flags);
    int gnutls_x509_crq_init (gnutls_x509_crq_t* crq);
    void gnutls_x509_crq_deinit (gnutls_x509_crq_t crq);
    int gnutls_x509_crq_import (gnutls_x509_crq_t crq, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
    int gnutls_x509_crq_get_private_key_usage_period (gnutls_x509_crq_t cert, time_t* activation, time_t* expiration, uint* critical);
    int gnutls_x509_crq_get_dn (gnutls_x509_crq_t crq, char* buf, size_t* sizeof_buf);
    int gnutls_x509_crq_get_dn2 (gnutls_x509_crq_t crq, gnutls_datum_t* dn);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_x509_crq_get_dn3 (gnutls_x509_crq_t crq, gnutls_datum_t* dn, uint flags);

    int gnutls_x509_crq_get_dn_oid (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid);
    int gnutls_x509_crq_get_dn_by_oid (gnutls_x509_crq_t crq, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
    int gnutls_x509_crq_set_dn (gnutls_x509_crq_t crq, const(char)* dn, const(char*)* err);
    int gnutls_x509_crq_set_dn_by_oid (gnutls_x509_crq_t crq, const(char)* oid, uint raw_flag, const(void)* data, uint sizeof_data);
    int gnutls_x509_crq_set_version (gnutls_x509_crq_t crq, uint version_);
    int gnutls_x509_crq_get_version (gnutls_x509_crq_t crq);
    int gnutls_x509_crq_set_key (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
        int gnutls_x509_crq_set_extension_by_oid (gnutls_x509_crq_t crq, const(char)* oid, const(void)* buf, size_t sizeof_buf, uint critical);

    int gnutls_x509_crq_set_challenge_password (gnutls_x509_crq_t crq, const(char)* pass);
    int gnutls_x509_crq_get_challenge_password (gnutls_x509_crq_t crq, char* pass, size_t* sizeof_pass);
    int gnutls_x509_crq_set_attribute_by_oid (gnutls_x509_crq_t crq, const(char)* oid, void* buf, size_t sizeof_buf);
    int gnutls_x509_crq_get_attribute_by_oid (gnutls_x509_crq_t crq, const(char)* oid, uint indx, void* buf, size_t* sizeof_buf);
    int gnutls_x509_crq_export (gnutls_x509_crq_t crq, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
    int gnutls_x509_crq_export2 (gnutls_x509_crq_t crq, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_x509_crt_set_crq (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq);
    int gnutls_x509_crt_set_crq_extensions (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        int gnutls_x509_crt_set_crq_extension_by_oid (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq, const(char)* oid, uint flags);

    int gnutls_x509_crq_set_private_key_usage_period (gnutls_x509_crq_t crq, time_t activation, time_t expiration);
    int gnutls_x509_crq_set_key_rsa_raw (gnutls_x509_crq_t crq, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e);
    int gnutls_x509_crq_set_subject_alt_name (gnutls_x509_crq_t crq, gnutls_x509_subject_alt_name_t nt, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crq_set_subject_alt_othername (gnutls_x509_crq_t crq, const(char)* oid, const(void)* data, uint data_size, uint flags);
    int gnutls_x509_crq_set_key_usage (gnutls_x509_crq_t crq, uint usage);
    int gnutls_x509_crq_set_basic_constraints (gnutls_x509_crq_t crq, uint ca, int pathLenConstraint);
    int gnutls_x509_crq_set_key_purpose_oid (gnutls_x509_crq_t crq, const(void)* oid, uint critical);
    int gnutls_x509_crq_get_key_purpose_oid (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
    int gnutls_x509_crq_get_extension_data (gnutls_x509_crq_t crq, uint indx, void* data, size_t* sizeof_data);
    int gnutls_x509_crq_get_extension_data2 (gnutls_x509_crq_t crq, uint indx, gnutls_datum_t* data);
    int gnutls_x509_crq_get_extension_info (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
    int gnutls_x509_crq_get_attribute_data (gnutls_x509_crq_t crq, uint indx, void* data, size_t* sizeof_data);
    int gnutls_x509_crq_get_attribute_info (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid);
    int gnutls_x509_crq_get_pk_algorithm (gnutls_x509_crq_t crq, uint* bits);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_x509_crq_get_spki (gnutls_x509_crq_t crq, gnutls_x509_spki_t spki, uint flags);
        int gnutls_x509_crq_set_spki (gnutls_x509_crq_t crq, const gnutls_x509_spki_t spki, uint flags);
    }

    int gnutls_x509_crq_get_signature_oid (gnutls_x509_crq_t crq, char* oid, size_t* oid_size);
    int gnutls_x509_crq_get_pk_oid (gnutls_x509_crq_t crq, char* oid, size_t* oid_size);
    int gnutls_x509_crq_get_key_id (gnutls_x509_crq_t crq, uint flags, ubyte* output_data, size_t* output_data_size);
    int gnutls_x509_crq_get_key_rsa_raw (gnutls_x509_crq_t crq, gnutls_datum_t* m, gnutls_datum_t* e);
    int gnutls_x509_crq_get_key_usage (gnutls_x509_crq_t crq, uint* key_usage, uint* critical);
    int gnutls_x509_crq_get_basic_constraints (gnutls_x509_crq_t crq, uint* critical, uint* ca, int* pathlen);
    int gnutls_x509_crq_get_subject_alt_name (gnutls_x509_crq_t crq, uint seq, void* ret, size_t* ret_size, uint* ret_type, uint* critical);
    int gnutls_x509_crq_get_subject_alt_othername_oid (gnutls_x509_crq_t crq, uint seq, void* ret, size_t* ret_size);
    int gnutls_x509_crq_get_extension_by_oid (gnutls_x509_crq_t crq, const(char)* oid, uint indx, void* buf, size_t* sizeof_buf, uint* critical);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
    {
        int gnutls_x509_crq_get_tlsfeatures (gnutls_x509_crq_t crq, gnutls_x509_tlsfeatures_t features, uint flags, uint* critical);
        int gnutls_x509_crq_set_tlsfeatures (gnutls_x509_crq_t crq, gnutls_x509_tlsfeatures_t features);
    }

    int gnutls_x509_crt_get_extension_by_oid2 (gnutls_x509_crt_t cert, const(char)* oid, uint indx, gnutls_datum_t* output, uint* critical);
    int gnutls_x509_trust_list_init (gnutls_x509_trust_list_t* list, uint size);
    void gnutls_x509_trust_list_deinit (gnutls_x509_trust_list_t list, uint all);
    int gnutls_x509_trust_list_get_issuer (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, gnutls_x509_crt_t* issuer, uint flags);
    int gnutls_x509_trust_list_get_issuer_by_dn (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* dn, gnutls_x509_crt_t* issuer, uint flags);
    int gnutls_x509_trust_list_get_issuer_by_subject_key_id (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* dn, const(gnutls_datum_t)* spki, gnutls_x509_crt_t* issuer, uint flags);
    int gnutls_x509_trust_list_add_cas (gnutls_x509_trust_list_t list, const(gnutls_x509_crt_t)* clist, uint clist_size, uint flags);
    int gnutls_x509_trust_list_remove_cas (gnutls_x509_trust_list_t list, const(gnutls_x509_crt_t)* clist, uint clist_size);
    int gnutls_x509_trust_list_add_named_crt (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, const(void)* name, size_t name_size, uint flags);
    int gnutls_x509_trust_list_add_crls (gnutls_x509_trust_list_t list, const(gnutls_x509_crl_t)* crl_list, uint crl_size, uint flags, uint verification_flags);
    int gnutls_x509_trust_list_iter_get_ca (gnutls_x509_trust_list_t list, gnutls_x509_trust_list_iter_t* iter, gnutls_x509_crt_t* crt);
    void gnutls_x509_trust_list_iter_deinit (gnutls_x509_trust_list_iter_t iter);
    int gnutls_x509_trust_list_verify_named_crt (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, const(void)* name, size_t name_size, uint flags, uint* verify, int function () func);
    int gnutls_x509_trust_list_verify_crt2 (gnutls_x509_trust_list_t list, gnutls_x509_crt_t* cert_list, uint cert_list_size, gnutls_typed_vdata_st* data, uint elements, uint flags, uint* voutput, int function () func);
    int gnutls_x509_trust_list_verify_crt (gnutls_x509_trust_list_t list, gnutls_x509_crt_t* cert_list, uint cert_list_size, uint flags, uint* verify, int function () func);
    int gnutls_x509_trust_list_add_trust_mem (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* cas, const(gnutls_datum_t)* crls, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
    int gnutls_x509_trust_list_add_trust_file (gnutls_x509_trust_list_t list, const(char)* ca_file, const(char)* crl_file, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
    int gnutls_x509_trust_list_add_trust_dir (gnutls_x509_trust_list_t list, const(char)* ca_dir, const(char)* crl_dir, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
    int gnutls_x509_trust_list_remove_trust_file (gnutls_x509_trust_list_t list, const(char)* ca_file, gnutls_x509_crt_fmt_t type);
    int gnutls_x509_trust_list_remove_trust_mem (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* cas, gnutls_x509_crt_fmt_t type);
    int gnutls_x509_trust_list_add_system_trust (gnutls_x509_trust_list_t list, uint tl_flags, uint tl_vflags);
    void gnutls_certificate_set_trust_list (gnutls_certificate_credentials_t res, gnutls_x509_trust_list_t tlist, uint flags);
    void gnutls_certificate_get_trust_list (gnutls_certificate_credentials_t res, gnutls_x509_trust_list_t* tlist);
    void gnutls_x509_ext_deinit (gnutls_x509_ext_st* ext);
    int gnutls_x509_ext_print (gnutls_x509_ext_st* exts, uint exts_size, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_x509_crt_init = int function (gnutls_x509_crt_t* cert);
        alias pgnutls_x509_crt_deinit = void function (gnutls_x509_crt_t cert);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            alias pgnutls_x509_crt_set_flags = void function (gnutls_x509_crt_t cert, uint flags);

        alias pgnutls_x509_crt_equals = uint function (gnutls_x509_crt_t cert1, gnutls_x509_crt_t cert2);
        alias pgnutls_x509_crt_equals2 = uint function (gnutls_x509_crt_t cert1, const(gnutls_datum_t)* der);
        alias pgnutls_x509_crt_import = int function (gnutls_x509_crt_t cert, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_x509_crt_list_import2 = int function (gnutls_x509_crt_t** certs, uint* size, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_x509_crt_list_import = int function (gnutls_x509_crt_t* certs, uint* cert_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_x509_crt_import_url = int function (gnutls_x509_crt_t crt, const(char)* url, uint flags);
        alias pgnutls_x509_crt_list_import_url = int function (gnutls_x509_crt_t** certs, uint* size, const(char)* url, gnutls_pin_callback_t pin_fn, void* pin_fn_userdata, uint flags);
        alias pgnutls_x509_crt_export = int function (gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_crt_export2 = int function (gnutls_x509_crt_t cert, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crt_get_private_key_usage_period = int function (gnutls_x509_crt_t cert, time_t* activation, time_t* expiration, uint* critical);
        alias pgnutls_x509_crt_get_issuer_dn = int function (gnutls_x509_crt_t cert, char* buf, size_t* buf_size);
        alias pgnutls_x509_crt_get_issuer_dn2 = int function (gnutls_x509_crt_t cert, gnutls_datum_t* dn);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_crt_get_issuer_dn3 = int function (gnutls_x509_crt_t cert, gnutls_datum_t* dn, uint flags);

        alias pgnutls_x509_crt_get_issuer_dn_oid = int function (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_issuer_dn_by_oid = int function (gnutls_x509_crt_t cert, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* buf_size);
        alias pgnutls_x509_crt_get_dn = int function (gnutls_x509_crt_t cert, char* buf, size_t* buf_size);
        alias pgnutls_x509_crt_get_dn2 = int function (gnutls_x509_crt_t cert, gnutls_datum_t* dn);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_crt_get_dn3 = int function (gnutls_x509_crt_t cert, gnutls_datum_t* dn, uint flags);

        alias pgnutls_x509_crt_get_dn_oid = int function (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_dn_by_oid = int function (gnutls_x509_crt_t cert, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* buf_size);
        alias pgnutls_x509_crt_check_hostname = uint function (gnutls_x509_crt_t cert, const(char)* hostname);
        alias pgnutls_x509_crt_check_hostname2 = uint function (gnutls_x509_crt_t cert, const(char)* hostname, uint flags);
        alias pgnutls_x509_crt_check_email = uint function (gnutls_x509_crt_t cert, const(char)* email, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            alias pgnutls_x509_crt_check_ip = uint function (gnutls_x509_crt_t cert, const(ubyte)* ip, uint ip_size, uint flags);

        alias pgnutls_x509_crt_get_signature_algorithm = int function (gnutls_x509_crt_t cert);
        alias pgnutls_x509_crt_get_signature = int function (gnutls_x509_crt_t cert, char* sig, size_t* sizeof_sig);
        alias pgnutls_x509_crt_get_version = int function (gnutls_x509_crt_t cert);
        alias pgnutls_x509_crt_get_pk_oid = int function (gnutls_x509_crt_t cert, char* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_signature_oid = int function (gnutls_x509_crt_t cert, char* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_key_id = int function (gnutls_x509_crt_t crt, uint flags, ubyte* output_data, size_t* output_data_size);
        alias pgnutls_x509_crt_set_private_key_usage_period = int function (gnutls_x509_crt_t crt, time_t activation, time_t expiration);
        alias pgnutls_x509_crt_set_authority_key_id = int function (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
        alias pgnutls_x509_crt_get_authority_key_id = int function (gnutls_x509_crt_t cert, void* id, size_t* id_size, uint* critical);
        alias pgnutls_x509_crt_get_authority_key_gn_serial = int function (gnutls_x509_crt_t cert, uint seq, void* alt, size_t* alt_size, uint* alt_type, void* serial, size_t* serial_size, uint* critical);
        alias pgnutls_x509_crt_get_subject_key_id = int function (gnutls_x509_crt_t cert, void* ret, size_t* ret_size, uint* critical);
        alias pgnutls_x509_crt_get_subject_unique_id = int function (gnutls_x509_crt_t crt, char* buf, size_t* buf_size);
        alias pgnutls_x509_crt_get_issuer_unique_id = int function (gnutls_x509_crt_t crt, char* buf, size_t* buf_size);
        alias pgnutls_x509_crt_set_pin_function = void function (gnutls_x509_crt_t crt, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_x509_crt_get_authority_info_access = int function (gnutls_x509_crt_t crt, uint seq, int what, gnutls_datum_t* data, uint* critical);
        alias pgnutls_x509_name_constraints_check = uint function (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
        alias pgnutls_x509_name_constraints_check_crt = uint function (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, gnutls_x509_crt_t crt);
        alias pgnutls_x509_name_constraints_init = int function (gnutls_x509_name_constraints_t* nc);
        alias pgnutls_x509_name_constraints_deinit = void function (gnutls_x509_name_constraints_t nc);
        alias pgnutls_x509_crt_get_name_constraints = int function (gnutls_x509_crt_t crt, gnutls_x509_name_constraints_t nc, uint flags, uint* critical);
        alias pgnutls_x509_name_constraints_add_permitted = int function (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
        alias pgnutls_x509_name_constraints_add_excluded = int function (gnutls_x509_name_constraints_t nc, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* name);
        alias pgnutls_x509_crt_set_name_constraints = int function (gnutls_x509_crt_t crt, gnutls_x509_name_constraints_t nc, uint critical);
        alias pgnutls_x509_name_constraints_get_permitted = int function (gnutls_x509_name_constraints_t nc, uint idx, uint* type, gnutls_datum_t* name);
        alias pgnutls_x509_name_constraints_get_excluded = int function (gnutls_x509_name_constraints_t nc, uint idx, uint* type, gnutls_datum_t* name);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            alias pgnutls_x509_cidr_to_rfc5280 = int function (const(char)* cidr, gnutls_datum_t* cidr_rfc5280);

        alias pgnutls_x509_crt_get_crl_dist_points = int function (gnutls_x509_crt_t cert, uint seq, void* ret, size_t* ret_size, uint* reason_flags, uint* critical);
        alias pgnutls_x509_crt_set_crl_dist_points2 = int function (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint reason_flags);
        alias pgnutls_x509_crt_set_crl_dist_points = int function (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data_string, uint reason_flags);
        alias pgnutls_x509_crt_cpy_crl_dist_points = int function (gnutls_x509_crt_t dst, gnutls_x509_crt_t src);
        alias pgnutls_x509_crl_sign = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key);
        alias pgnutls_x509_crl_sign2 = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_x509_crt_get_activation_time = time_t function (gnutls_x509_crt_t cert);
        alias pgnutls_x509_crt_get_expiration_time = time_t function (gnutls_x509_crt_t cert);
        alias pgnutls_x509_crt_get_serial = int function (gnutls_x509_crt_t cert, void* result, size_t* result_size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_x509_spki_init = int function (gnutls_x509_spki_t* spki);
            alias pgnutls_x509_spki_deinit = void function (gnutls_x509_spki_t spki);
        }

        alias pgnutls_x509_spki_get_rsa_pss_params = int function (gnutls_x509_spki_t spki, gnutls_digest_algorithm_t* dig, uint* salt_size);
        alias pgnutls_x509_spki_set_rsa_pss_params = void function (gnutls_x509_spki_t spki, gnutls_digest_algorithm_t dig, uint salt_size);
        alias pgnutls_x509_crt_get_pk_algorithm = int function (gnutls_x509_crt_t cert, uint* bits);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_x509_crt_set_spki = int function (gnutls_x509_crt_t crt, const gnutls_x509_spki_t spki, uint flags);
            alias pgnutls_x509_crt_get_spki = int function (gnutls_x509_crt_t cert, gnutls_x509_spki_t spki, uint flags);
        }

        alias pgnutls_x509_crt_get_pk_rsa_raw = int function (gnutls_x509_crt_t crt, gnutls_datum_t* m, gnutls_datum_t* e);
        alias pgnutls_x509_crt_get_pk_dsa_raw = int function (gnutls_x509_crt_t crt, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);
        alias pgnutls_x509_crt_get_pk_ecc_raw = int function (gnutls_x509_crt_t crt, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y);
        alias pgnutls_x509_crt_get_pk_gost_raw = int function (gnutls_x509_crt_t crt, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y);
        alias pgnutls_x509_crt_get_subject_alt_name = int function (gnutls_x509_crt_t cert, uint seq, void* san, size_t* san_size, uint* critical);
        alias pgnutls_x509_crt_get_subject_alt_name2 = int function (gnutls_x509_crt_t cert, uint seq, void* san, size_t* san_size, uint* san_type, uint* critical);
        alias pgnutls_x509_crt_get_subject_alt_othername_oid = int function (gnutls_x509_crt_t cert, uint seq, void* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_issuer_alt_name = int function (gnutls_x509_crt_t cert, uint seq, void* ian, size_t* ian_size, uint* critical);
        alias pgnutls_x509_crt_get_issuer_alt_name2 = int function (gnutls_x509_crt_t cert, uint seq, void* ian, size_t* ian_size, uint* ian_type, uint* critical);
        alias pgnutls_x509_crt_get_issuer_alt_othername_oid = int function (gnutls_x509_crt_t cert, uint seq, void* ret, size_t* ret_size);
        alias pgnutls_x509_crt_get_ca_status = int function (gnutls_x509_crt_t cert, uint* critical);
        alias pgnutls_x509_crt_get_basic_constraints = int function (gnutls_x509_crt_t cert, uint* critical, uint* ca, int* pathlen);
        alias pgnutls_x509_crt_get_key_usage = int function (gnutls_x509_crt_t cert, uint* key_usage, uint* critical);
        alias pgnutls_x509_crt_set_key_usage = int function (gnutls_x509_crt_t crt, uint usage);
        alias pgnutls_x509_crt_set_authority_info_access = int function (gnutls_x509_crt_t crt, int what, gnutls_datum_t* data);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_x509_crt_get_inhibit_anypolicy = int function (gnutls_x509_crt_t cert, uint* skipcerts, uint* critical);
            alias pgnutls_x509_crt_set_inhibit_anypolicy = int function (gnutls_x509_crt_t crt, uint skipcerts);
        }

        alias pgnutls_x509_crt_get_proxy = int function (gnutls_x509_crt_t cert, uint* critical, int* pathlen, char** policyLanguage, char** policy, size_t* sizeof_policy);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            alias pgnutls_x509_tlsfeatures_init = int function (gnutls_x509_tlsfeatures_t* features);
            alias pgnutls_x509_tlsfeatures_deinit = void function (gnutls_x509_tlsfeatures_t);
            alias pgnutls_x509_tlsfeatures_get = int function (gnutls_x509_tlsfeatures_t f, uint idx, uint* feature);
            alias pgnutls_x509_crt_set_tlsfeatures = int function (gnutls_x509_crt_t crt, gnutls_x509_tlsfeatures_t features);
            alias pgnutls_x509_crt_get_tlsfeatures = int function (gnutls_x509_crt_t cert, gnutls_x509_tlsfeatures_t features, uint flags, uint* critical);
        }

        alias pgnutls_x509_tlsfeatures_check_crt = uint function (gnutls_x509_tlsfeatures_t feat, gnutls_x509_crt_t crt);
        alias pgnutls_x509_policy_release = void function (gnutls_x509_policy_st* policy);
        alias pgnutls_x509_crt_get_policy = int function (gnutls_x509_crt_t crt, uint indx, gnutls_x509_policy_st* policy, uint* critical);
        alias pgnutls_x509_crt_set_policy = int function (gnutls_x509_crt_t crt, const(gnutls_x509_policy_st)* policy, uint critical);
        alias pgnutls_x509_dn_oid_known = int function (const(char)* oid);
        alias pgnutls_x509_dn_oid_name = const(char)* function (const(char)* oid, uint flags);
        alias pgnutls_x509_crt_get_extension_oid = int function (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size);
        alias pgnutls_x509_crt_get_extension_by_oid = int function (gnutls_x509_crt_t cert, const(char)* oid, uint indx, void* buf, size_t* buf_size, uint* critical);
        alias pgnutls_x509_crq_get_signature_algorithm = int function (gnutls_x509_crq_t crq);
        alias pgnutls_x509_crq_get_extension_by_oid2 = int function (gnutls_x509_crq_t crq, const(char)* oid, uint indx, gnutls_datum_t* output, uint* critical);
        alias pgnutls_x509_crt_get_extension_info = int function (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size, uint* critical);
        alias pgnutls_x509_crt_get_extension_data = int function (gnutls_x509_crt_t cert, uint indx, void* data, size_t* sizeof_data);
        alias pgnutls_x509_crt_get_extension_data2 = int function (gnutls_x509_crt_t cert, uint indx, gnutls_datum_t* data);
        alias pgnutls_x509_crt_set_extension_by_oid = int function (gnutls_x509_crt_t crt, const(char)* oid, const(void)* buf, size_t sizeof_buf, uint critical);
        alias pgnutls_x509_crt_set_dn = int function (gnutls_x509_crt_t crt, const(char)* dn, const(char*)* err);
        alias pgnutls_x509_crt_set_dn_by_oid = int function (gnutls_x509_crt_t crt, const(char)* oid, uint raw_flag, const(void)* name, uint sizeof_name);
        alias pgnutls_x509_crt_set_issuer_dn_by_oid = int function (gnutls_x509_crt_t crt, const(char)* oid, uint raw_flag, const(void)* name, uint sizeof_name);
        alias pgnutls_x509_crt_set_issuer_dn = int function (gnutls_x509_crt_t crt, const(char)* dn, const(char*)* err);
        alias pgnutls_x509_crt_set_version = int function (gnutls_x509_crt_t crt, uint version_);
        alias pgnutls_x509_crt_set_key = int function (gnutls_x509_crt_t crt, gnutls_x509_privkey_t key);
        alias pgnutls_x509_crt_set_ca_status = int function (gnutls_x509_crt_t crt, uint ca);
        alias pgnutls_x509_crt_set_basic_constraints = int function (gnutls_x509_crt_t crt, uint ca, int pathLenConstraint);
        alias pgnutls_x509_crt_set_subject_unique_id = int function (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
        alias pgnutls_x509_crt_set_issuer_unique_id = int function (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
        alias pgnutls_x509_crt_set_subject_alternative_name = int function (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(char)* data_string);
        alias pgnutls_x509_crt_set_subject_alt_name = int function (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crt_set_subject_alt_othername = int function (gnutls_x509_crt_t crt, const(char)* oid, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crt_set_issuer_alt_name = int function (gnutls_x509_crt_t crt, gnutls_x509_subject_alt_name_t type, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crt_set_issuer_alt_othername = int function (gnutls_x509_crt_t crt, const(char)* oid, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crt_sign = int function (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key);
        alias pgnutls_x509_crt_sign2 = int function (gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer, gnutls_x509_privkey_t issuer_key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_x509_crt_set_activation_time = int function (gnutls_x509_crt_t cert, time_t act_time);
        alias pgnutls_x509_crt_set_expiration_time = int function (gnutls_x509_crt_t cert, time_t exp_time);
        alias pgnutls_x509_crt_set_serial = int function (gnutls_x509_crt_t cert, const(void)* serial, size_t serial_size);
        alias pgnutls_x509_crt_set_subject_key_id = int function (gnutls_x509_crt_t cert, const(void)* id, size_t id_size);
        alias pgnutls_x509_crt_set_proxy_dn = int function (gnutls_x509_crt_t crt, gnutls_x509_crt_t eecrt, uint raw_flag, const(void)* name, uint sizeof_name);
        alias pgnutls_x509_crt_set_proxy = int function (gnutls_x509_crt_t crt, int pathLenConstraint, const(char)* policyLanguage, const(char)* policy, size_t sizeof_policy);
        alias pgnutls_x509_crt_print = int function (gnutls_x509_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crl_print = int function (gnutls_x509_crl_t crl, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crt_get_raw_issuer_dn = int function (gnutls_x509_crt_t cert, gnutls_datum_t* start);
        alias pgnutls_x509_crt_get_raw_dn = int function (gnutls_x509_crt_t cert, gnutls_datum_t* start);
        alias pgnutls_x509_rdn_get = int function (const(gnutls_datum_t)* idn, char* buf, size_t* sizeof_buf);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_rdn_get2 = int function (const(gnutls_datum_t)* idn, gnutls_datum_t* str, uint flags);

        alias pgnutls_x509_rdn_get_oid = int function (const(gnutls_datum_t)* idn, uint indx, void* buf, size_t* sizeof_buf);
        alias pgnutls_x509_rdn_get_by_oid = int function (const(gnutls_datum_t)* idn, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crt_get_subject = int function (gnutls_x509_crt_t cert, gnutls_x509_dn_t* dn);
        alias pgnutls_x509_crt_get_issuer = int function (gnutls_x509_crt_t cert, gnutls_x509_dn_t* dn);
        alias pgnutls_x509_dn_get_rdn_ava = int function (gnutls_x509_dn_t dn, int irdn, int iava, gnutls_x509_ava_st* ava);
        alias pgnutls_x509_dn_get_str = int function (gnutls_x509_dn_t dn, gnutls_datum_t* str);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_dn_get_str2 = int function (gnutls_x509_dn_t dn, gnutls_datum_t* str, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            alias pgnutls_x509_dn_set_str = int function (gnutls_x509_dn_t dn, const(char)* str, const(char*)* err);

        alias pgnutls_x509_dn_init = int function (gnutls_x509_dn_t* dn);
        alias pgnutls_x509_dn_import = int function (gnutls_x509_dn_t dn, const(gnutls_datum_t)* data);
        alias pgnutls_x509_dn_export = int function (gnutls_x509_dn_t dn, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_dn_export2 = int function (gnutls_x509_dn_t dn, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_dn_deinit = void function (gnutls_x509_dn_t dn);
        alias pgnutls_x509_crl_init = int function (gnutls_x509_crl_t* crl);
        alias pgnutls_x509_crl_deinit = void function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_import = int function (gnutls_x509_crl_t crl, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_x509_crl_export = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_crl_export2 = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crl_get_raw_issuer_dn = int function (gnutls_x509_crl_t crl, gnutls_datum_t* dn);
        alias pgnutls_x509_crl_get_issuer_dn = int function (gnutls_x509_crl_t crl, char* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crl_get_issuer_dn2 = int function (gnutls_x509_crl_t crl, gnutls_datum_t* dn);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_crl_get_issuer_dn3 = int function (gnutls_x509_crl_t crl, gnutls_datum_t* dn, uint flags);

        alias pgnutls_x509_crl_get_issuer_dn_by_oid = int function (gnutls_x509_crl_t crl, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crl_get_dn_oid = int function (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid);
        alias pgnutls_x509_crl_get_signature_algorithm = int function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_get_signature = int function (gnutls_x509_crl_t crl, char* sig, size_t* sizeof_sig);
        alias pgnutls_x509_crl_get_version = int function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_get_signature_oid = int function (gnutls_x509_crl_t crl, char* oid, size_t* oid_size);
        alias pgnutls_x509_crl_get_this_update = time_t function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_get_next_update = time_t function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_get_crt_count = int function (gnutls_x509_crl_t crl);
        alias pgnutls_x509_crl_get_crt_serial = int function (gnutls_x509_crl_t crl, uint indx, ubyte* serial, size_t* serial_size, time_t* t);
        alias pgnutls_x509_crl_iter_crt_serial = int function (gnutls_x509_crl_t crl, gnutls_x509_crl_iter_t*, ubyte* serial, size_t* serial_size, time_t* t);
        alias pgnutls_x509_crl_iter_deinit = void function (gnutls_x509_crl_iter_t);
        alias pgnutls_x509_crl_check_issuer = uint function (gnutls_x509_crl_t crl, gnutls_x509_crt_t issuer);
        alias pgnutls_x509_crl_list_import2 = int function (gnutls_x509_crl_t** crls, uint* size, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_x509_crl_list_import = int function (gnutls_x509_crl_t* crls, uint* crl_max, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint flags);
        alias pgnutls_x509_crl_set_version = int function (gnutls_x509_crl_t crl, uint version_);
        alias pgnutls_x509_crl_set_this_update = int function (gnutls_x509_crl_t crl, time_t act_time);
        alias pgnutls_x509_crl_set_next_update = int function (gnutls_x509_crl_t crl, time_t exp_time);
        alias pgnutls_x509_crl_set_crt_serial = int function (gnutls_x509_crl_t crl, const(void)* serial, size_t serial_size, time_t revocation_time);
        alias pgnutls_x509_crl_set_crt = int function (gnutls_x509_crl_t crl, gnutls_x509_crt_t crt, time_t revocation_time);
        alias pgnutls_x509_crl_get_authority_key_id = int function (gnutls_x509_crl_t crl, void* id, size_t* id_size, uint* critical);
        alias pgnutls_x509_crl_get_authority_key_gn_serial = int function (gnutls_x509_crl_t crl, uint seq, void* alt, size_t* alt_size, uint* alt_type, void* serial, size_t* serial_size, uint* critical);
        alias pgnutls_x509_crl_get_number = int function (gnutls_x509_crl_t crl, void* ret, size_t* ret_size, uint* critical);
        alias pgnutls_x509_crl_get_extension_oid = int function (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid);
        alias pgnutls_x509_crl_get_extension_info = int function (gnutls_x509_crl_t crl, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
        alias pgnutls_x509_crl_get_extension_data = int function (gnutls_x509_crl_t crl, uint indx, void* data, size_t* sizeof_data);
        alias pgnutls_x509_crl_get_extension_data2 = int function (gnutls_x509_crl_t crl, uint indx, gnutls_datum_t* data);
        alias pgnutls_x509_crl_set_authority_key_id = int function (gnutls_x509_crl_t crl, const(void)* id, size_t id_size);
        alias pgnutls_x509_crl_set_number = int function (gnutls_x509_crl_t crl, const(void)* nr, size_t nr_size);
        alias pgnutls_certificate_verification_profile_get_name = const(char)* function (gnutls_certificate_verification_profiles_t id);
        alias pgnutls_certificate_verification_profile_get_id = gnutls_certificate_verification_profiles_t function (const(char)* name);
        alias pgnutls_x509_crt_check_issuer = uint function (gnutls_x509_crt_t cert, gnutls_x509_crt_t issuer);
        alias pgnutls_x509_crt_list_verify = int function (const(gnutls_x509_crt_t)* cert_list, uint cert_list_length, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, const(gnutls_x509_crl_t)* CRL_list, uint CRL_list_length, uint flags, uint* verify);
        alias pgnutls_x509_crt_verify = int function (gnutls_x509_crt_t cert, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, uint flags, uint* verify);
        alias pgnutls_x509_crl_verify = int function (gnutls_x509_crl_t crl, const(gnutls_x509_crt_t)* CA_list, uint CA_list_length, uint flags, uint* verify);
        alias pgnutls_x509_crt_verify_data2 = int function (gnutls_x509_crt_t crt, gnutls_sign_algorithm_t algo, uint flags, const(gnutls_datum_t)* data, const(gnutls_datum_t)* signature);
        alias pgnutls_x509_crt_check_revocation = int function (gnutls_x509_crt_t cert, const(gnutls_x509_crl_t)* crl_list, uint crl_list_length);
        alias pgnutls_x509_crt_get_fingerprint = int function (gnutls_x509_crt_t cert, gnutls_digest_algorithm_t algo, void* buf, size_t* buf_size);
        alias pgnutls_x509_crt_get_key_purpose_oid = int function (gnutls_x509_crt_t cert, uint indx, void* oid, size_t* oid_size, uint* critical);
        alias pgnutls_x509_crt_set_key_purpose_oid = int function (gnutls_x509_crt_t cert, const(void)* oid, uint critical);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            alias pgnutls_x509_crt_check_key_purpose = uint function (gnutls_x509_crt_t cert, const(char)* purpose, uint flags);

        alias pgnutls_pkcs_schema_get_name = const(char)* function (uint schema);
        alias pgnutls_pkcs_schema_get_oid = const(char)* function (uint schema);
        alias pgnutls_x509_privkey_init = int function (gnutls_x509_privkey_t* key);
        alias pgnutls_x509_privkey_deinit = void function (gnutls_x509_privkey_t key);
        alias pgnutls_x509_privkey_sec_param = gnutls_sec_param_t function (gnutls_x509_privkey_t key);
        alias pgnutls_x509_privkey_set_pin_function = void function (gnutls_x509_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_x509_privkey_cpy = int function (gnutls_x509_privkey_t dst, gnutls_x509_privkey_t src);
        alias pgnutls_x509_privkey_import = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_x509_privkey_import_pkcs8 = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);
        alias pgnutls_x509_privkey_import_openssl = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, const(char)* password);
        alias pgnutls_pkcs8_info = int function (const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, uint* schema, uint* cipher, void* salt, uint* salt_size, uint* iter_count, char** oid);
        alias pgnutls_x509_privkey_import2 = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags);
        alias pgnutls_x509_privkey_import_rsa_raw = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u);
        alias pgnutls_x509_privkey_import_rsa_raw2 = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e, const(gnutls_datum_t)* d, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* u, const(gnutls_datum_t)* e1, const(gnutls_datum_t)* e2);
        alias pgnutls_x509_privkey_import_ecc_raw = int function (gnutls_x509_privkey_t key, gnutls_ecc_curve_t curve, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);
        alias pgnutls_x509_privkey_import_gost_raw = int function (gnutls_x509_privkey_t key, gnutls_ecc_curve_t curve, gnutls_digest_algorithm_t digest, gnutls_gost_paramset_t paramset, const(gnutls_datum_t)* x, const(gnutls_datum_t)* y, const(gnutls_datum_t)* k);
        alias pgnutls_x509_privkey_fix = int function (gnutls_x509_privkey_t key);
        alias pgnutls_x509_privkey_export_dsa_raw = int function (gnutls_x509_privkey_t key, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
        alias pgnutls_x509_privkey_import_dsa_raw = int function (gnutls_x509_privkey_t key, const(gnutls_datum_t)* p, const(gnutls_datum_t)* q, const(gnutls_datum_t)* g, const(gnutls_datum_t)* y, const(gnutls_datum_t)* x);
        alias pgnutls_x509_privkey_get_pk_algorithm = int function (gnutls_x509_privkey_t key);
        alias pgnutls_x509_privkey_get_pk_algorithm2 = int function (gnutls_x509_privkey_t key, uint* bits);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_x509_privkey_get_spki = int function (gnutls_x509_privkey_t key, gnutls_x509_spki_t spki, uint flags);
            alias pgnutls_x509_privkey_set_spki = int function (gnutls_x509_privkey_t key, const gnutls_x509_spki_t spki, uint flags);
        }

        alias pgnutls_x509_privkey_get_key_id = int function (gnutls_x509_privkey_t key, uint flags, ubyte* output_data, size_t* output_data_size);
        alias pgnutls_x509_privkey_generate = int function (gnutls_x509_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags);
        alias pgnutls_x509_privkey_set_flags = void function (gnutls_x509_privkey_t key, uint flags);
        alias pgnutls_x509_privkey_generate2 = int function (gnutls_x509_privkey_t key, gnutls_pk_algorithm_t algo, uint bits, uint flags, const(gnutls_keygen_data_st)* data, uint data_size);
        alias pgnutls_x509_privkey_verify_seed = int function (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t, const(void)* seed, size_t seed_size);
        alias pgnutls_x509_privkey_get_seed = int function (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t*, void* seed, size_t* seed_size);
        alias pgnutls_x509_privkey_verify_params = int function (gnutls_x509_privkey_t key);
        alias pgnutls_x509_privkey_export = int function (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_privkey_export2 = int function (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_privkey_export_pkcs8 = int function (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_privkey_export2_pkcs8 = int function (gnutls_x509_privkey_t key, gnutls_x509_crt_fmt_t format, const(char)* password, uint flags, gnutls_datum_t* out_);
        alias pgnutls_x509_privkey_export_rsa_raw2 = int function (gnutls_x509_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u, gnutls_datum_t* e1, gnutls_datum_t* e2);
        alias pgnutls_x509_privkey_export_rsa_raw = int function (gnutls_x509_privkey_t key, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u);
        alias pgnutls_x509_privkey_export_ecc_raw = int function (gnutls_x509_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);
        alias pgnutls_x509_privkey_export_gost_raw = int function (gnutls_x509_privkey_t key, gnutls_ecc_curve_t* curve, gnutls_digest_algorithm_t* digest, gnutls_gost_paramset_t* paramset, gnutls_datum_t* x, gnutls_datum_t* y, gnutls_datum_t* k);
        alias pgnutls_x509_privkey_sign_data = int function (gnutls_x509_privkey_t key, gnutls_digest_algorithm_t digest, uint flags, const(gnutls_datum_t)* data, void* signature, size_t* signature_size);
        alias pgnutls_x509_crq_sign = int function (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key);
        alias pgnutls_x509_crq_sign2 = int function (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key, gnutls_digest_algorithm_t dig, uint flags);
        alias pgnutls_x509_crq_print = int function (gnutls_x509_crq_t crq, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crq_verify = int function (gnutls_x509_crq_t crq, uint flags);
        alias pgnutls_x509_crq_init = int function (gnutls_x509_crq_t* crq);
        alias pgnutls_x509_crq_deinit = void function (gnutls_x509_crq_t crq);
        alias pgnutls_x509_crq_import = int function (gnutls_x509_crq_t crq, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t format);
        alias pgnutls_x509_crq_get_private_key_usage_period = int function (gnutls_x509_crq_t cert, time_t* activation, time_t* expiration, uint* critical);
        alias pgnutls_x509_crq_get_dn = int function (gnutls_x509_crq_t crq, char* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crq_get_dn2 = int function (gnutls_x509_crq_t crq, gnutls_datum_t* dn);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_x509_crq_get_dn3 = int function (gnutls_x509_crq_t crq, gnutls_datum_t* dn, uint flags);

        alias pgnutls_x509_crq_get_dn_oid = int function (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid);
        alias pgnutls_x509_crq_get_dn_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, uint indx, uint raw_flag, void* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crq_set_dn = int function (gnutls_x509_crq_t crq, const(char)* dn, const(char*)* err);
        alias pgnutls_x509_crq_set_dn_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, uint raw_flag, const(void)* data, uint sizeof_data);
        alias pgnutls_x509_crq_set_version = int function (gnutls_x509_crq_t crq, uint version_);
        alias pgnutls_x509_crq_get_version = int function (gnutls_x509_crq_t crq);
        alias pgnutls_x509_crq_set_key = int function (gnutls_x509_crq_t crq, gnutls_x509_privkey_t key);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            alias pgnutls_x509_crq_set_extension_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, const(void)* buf, size_t sizeof_buf, uint critical);

        alias pgnutls_x509_crq_set_challenge_password = int function (gnutls_x509_crq_t crq, const(char)* pass);
        alias pgnutls_x509_crq_get_challenge_password = int function (gnutls_x509_crq_t crq, char* pass, size_t* sizeof_pass);
        alias pgnutls_x509_crq_set_attribute_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, void* buf, size_t sizeof_buf);
        alias pgnutls_x509_crq_get_attribute_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, uint indx, void* buf, size_t* sizeof_buf);
        alias pgnutls_x509_crq_export = int function (gnutls_x509_crq_t crq, gnutls_x509_crt_fmt_t format, void* output_data, size_t* output_data_size);
        alias pgnutls_x509_crq_export2 = int function (gnutls_x509_crq_t crq, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_x509_crt_set_crq = int function (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq);
        alias pgnutls_x509_crt_set_crq_extensions = int function (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            alias pgnutls_x509_crt_set_crq_extension_by_oid = int function (gnutls_x509_crt_t crt, gnutls_x509_crq_t crq, const(char)* oid, uint flags);

        alias pgnutls_x509_crq_set_private_key_usage_period = int function (gnutls_x509_crq_t crq, time_t activation, time_t expiration);
        alias pgnutls_x509_crq_set_key_rsa_raw = int function (gnutls_x509_crq_t crq, const(gnutls_datum_t)* m, const(gnutls_datum_t)* e);
        alias pgnutls_x509_crq_set_subject_alt_name = int function (gnutls_x509_crq_t crq, gnutls_x509_subject_alt_name_t nt, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crq_set_subject_alt_othername = int function (gnutls_x509_crq_t crq, const(char)* oid, const(void)* data, uint data_size, uint flags);
        alias pgnutls_x509_crq_set_key_usage = int function (gnutls_x509_crq_t crq, uint usage);
        alias pgnutls_x509_crq_set_basic_constraints = int function (gnutls_x509_crq_t crq, uint ca, int pathLenConstraint);
        alias pgnutls_x509_crq_set_key_purpose_oid = int function (gnutls_x509_crq_t crq, const(void)* oid, uint critical);
        alias pgnutls_x509_crq_get_key_purpose_oid = int function (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
        alias pgnutls_x509_crq_get_extension_data = int function (gnutls_x509_crq_t crq, uint indx, void* data, size_t* sizeof_data);
        alias pgnutls_x509_crq_get_extension_data2 = int function (gnutls_x509_crq_t crq, uint indx, gnutls_datum_t* data);
        alias pgnutls_x509_crq_get_extension_info = int function (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid, uint* critical);
        alias pgnutls_x509_crq_get_attribute_data = int function (gnutls_x509_crq_t crq, uint indx, void* data, size_t* sizeof_data);
        alias pgnutls_x509_crq_get_attribute_info = int function (gnutls_x509_crq_t crq, uint indx, void* oid, size_t* sizeof_oid);
        alias pgnutls_x509_crq_get_pk_algorithm = int function (gnutls_x509_crq_t crq, uint* bits);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_x509_crq_get_spki = int function (gnutls_x509_crq_t crq, gnutls_x509_spki_t spki, uint flags);
            alias pgnutls_x509_crq_set_spki = int function (gnutls_x509_crq_t crq, const gnutls_x509_spki_t spki, uint flags);
        }

        alias pgnutls_x509_crq_get_signature_oid = int function (gnutls_x509_crq_t crq, char* oid, size_t* oid_size);
        alias pgnutls_x509_crq_get_pk_oid = int function (gnutls_x509_crq_t crq, char* oid, size_t* oid_size);
        alias pgnutls_x509_crq_get_key_id = int function (gnutls_x509_crq_t crq, uint flags, ubyte* output_data, size_t* output_data_size);
        alias pgnutls_x509_crq_get_key_rsa_raw = int function (gnutls_x509_crq_t crq, gnutls_datum_t* m, gnutls_datum_t* e);
        alias pgnutls_x509_crq_get_key_usage = int function (gnutls_x509_crq_t crq, uint* key_usage, uint* critical);
        alias pgnutls_x509_crq_get_basic_constraints = int function (gnutls_x509_crq_t crq, uint* critical, uint* ca, int* pathlen);
        alias pgnutls_x509_crq_get_subject_alt_name = int function (gnutls_x509_crq_t crq, uint seq, void* ret, size_t* ret_size, uint* ret_type, uint* critical);
        alias pgnutls_x509_crq_get_subject_alt_othername_oid = int function (gnutls_x509_crq_t crq, uint seq, void* ret, size_t* ret_size);
        alias pgnutls_x509_crq_get_extension_by_oid = int function (gnutls_x509_crq_t crq, const(char)* oid, uint indx, void* buf, size_t* sizeof_buf, uint* critical);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            alias pgnutls_x509_crq_get_tlsfeatures = int function (gnutls_x509_crq_t crq, gnutls_x509_tlsfeatures_t features, uint flags, uint* critical);
            alias pgnutls_x509_crq_set_tlsfeatures = int function (gnutls_x509_crq_t crq, gnutls_x509_tlsfeatures_t features);
        }

        alias pgnutls_x509_crt_get_extension_by_oid2 = int function (gnutls_x509_crt_t cert, const(char)* oid, uint indx, gnutls_datum_t* output, uint* critical);
        alias pgnutls_x509_trust_list_init = int function (gnutls_x509_trust_list_t* list, uint size);
        alias pgnutls_x509_trust_list_deinit = void function (gnutls_x509_trust_list_t list, uint all);
        alias pgnutls_x509_trust_list_get_issuer = int function (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, gnutls_x509_crt_t* issuer, uint flags);
        alias pgnutls_x509_trust_list_get_issuer_by_dn = int function (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* dn, gnutls_x509_crt_t* issuer, uint flags);
        alias pgnutls_x509_trust_list_get_issuer_by_subject_key_id = int function (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* dn, const(gnutls_datum_t)* spki, gnutls_x509_crt_t* issuer, uint flags);
        alias pgnutls_x509_trust_list_add_cas = int function (gnutls_x509_trust_list_t list, const(gnutls_x509_crt_t)* clist, uint clist_size, uint flags);
        alias pgnutls_x509_trust_list_remove_cas = int function (gnutls_x509_trust_list_t list, const(gnutls_x509_crt_t)* clist, uint clist_size);
        alias pgnutls_x509_trust_list_add_named_crt = int function (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, const(void)* name, size_t name_size, uint flags);
        alias pgnutls_x509_trust_list_add_crls = int function (gnutls_x509_trust_list_t list, const(gnutls_x509_crl_t)* crl_list, uint crl_size, uint flags, uint verification_flags);
        alias pgnutls_x509_trust_list_iter_get_ca = int function (gnutls_x509_trust_list_t list, gnutls_x509_trust_list_iter_t* iter, gnutls_x509_crt_t* crt);
        alias pgnutls_x509_trust_list_iter_deinit = void function (gnutls_x509_trust_list_iter_t iter);
        alias pgnutls_x509_trust_list_verify_named_crt = int function (gnutls_x509_trust_list_t list, gnutls_x509_crt_t cert, const(void)* name, size_t name_size, uint flags, uint* verify, int function () func);
        alias pgnutls_x509_trust_list_verify_crt2 = int function (gnutls_x509_trust_list_t list, gnutls_x509_crt_t* cert_list, uint cert_list_size, gnutls_typed_vdata_st* data, uint elements, uint flags, uint* voutput, int function () func);
        alias pgnutls_x509_trust_list_verify_crt = int function (gnutls_x509_trust_list_t list, gnutls_x509_crt_t* cert_list, uint cert_list_size, uint flags, uint* verify, int function () func);
        alias pgnutls_x509_trust_list_add_trust_mem = int function (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* cas, const(gnutls_datum_t)* crls, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
        alias pgnutls_x509_trust_list_add_trust_file = int function (gnutls_x509_trust_list_t list, const(char)* ca_file, const(char)* crl_file, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
        alias pgnutls_x509_trust_list_add_trust_dir = int function (gnutls_x509_trust_list_t list, const(char)* ca_dir, const(char)* crl_dir, gnutls_x509_crt_fmt_t type, uint tl_flags, uint tl_vflags);
        alias pgnutls_x509_trust_list_remove_trust_file = int function (gnutls_x509_trust_list_t list, const(char)* ca_file, gnutls_x509_crt_fmt_t type);
        alias pgnutls_x509_trust_list_remove_trust_mem = int function (gnutls_x509_trust_list_t list, const(gnutls_datum_t)* cas, gnutls_x509_crt_fmt_t type);
        alias pgnutls_x509_trust_list_add_system_trust = int function (gnutls_x509_trust_list_t list, uint tl_flags, uint tl_vflags);
        alias pgnutls_certificate_set_trust_list = void function (gnutls_certificate_credentials_t res, gnutls_x509_trust_list_t tlist, uint flags);
        alias pgnutls_certificate_get_trust_list = void function (gnutls_certificate_credentials_t res, gnutls_x509_trust_list_t* tlist);
        alias pgnutls_x509_ext_deinit = void function (gnutls_x509_ext_st* ext);
        alias pgnutls_x509_ext_print = int function (gnutls_x509_ext_st* exts, uint exts_size, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);
    }

    __gshared
    {
        pgnutls_x509_crt_init gnutls_x509_crt_init;
        pgnutls_x509_crt_deinit gnutls_x509_crt_deinit;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            pgnutls_x509_crt_set_flags gnutls_x509_crt_set_flags;

        pgnutls_x509_crt_equals gnutls_x509_crt_equals;
        pgnutls_x509_crt_equals2 gnutls_x509_crt_equals2;
        pgnutls_x509_crt_import gnutls_x509_crt_import;
        pgnutls_x509_crt_list_import2 gnutls_x509_crt_list_import2;
        pgnutls_x509_crt_list_import gnutls_x509_crt_list_import;
        pgnutls_x509_crt_import_url gnutls_x509_crt_import_url;
        pgnutls_x509_crt_list_import_url gnutls_x509_crt_list_import_url;
        pgnutls_x509_crt_export gnutls_x509_crt_export;
        pgnutls_x509_crt_export2 gnutls_x509_crt_export2;
        pgnutls_x509_crt_get_private_key_usage_period gnutls_x509_crt_get_private_key_usage_period;
        pgnutls_x509_crt_get_issuer_dn gnutls_x509_crt_get_issuer_dn;
        pgnutls_x509_crt_get_issuer_dn2 gnutls_x509_crt_get_issuer_dn2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_crt_get_issuer_dn3 gnutls_x509_crt_get_issuer_dn3;

        pgnutls_x509_crt_get_issuer_dn_oid gnutls_x509_crt_get_issuer_dn_oid;
        pgnutls_x509_crt_get_issuer_dn_by_oid gnutls_x509_crt_get_issuer_dn_by_oid;
        pgnutls_x509_crt_get_dn gnutls_x509_crt_get_dn;
        pgnutls_x509_crt_get_dn2 gnutls_x509_crt_get_dn2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_crt_get_dn3 gnutls_x509_crt_get_dn3;

        pgnutls_x509_crt_get_dn_oid gnutls_x509_crt_get_dn_oid;
        pgnutls_x509_crt_get_dn_by_oid gnutls_x509_crt_get_dn_by_oid;
        pgnutls_x509_crt_check_hostname gnutls_x509_crt_check_hostname;
        pgnutls_x509_crt_check_hostname2 gnutls_x509_crt_check_hostname2;
        pgnutls_x509_crt_check_email gnutls_x509_crt_check_email;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            pgnutls_x509_crt_check_ip gnutls_x509_crt_check_ip;

        pgnutls_x509_crt_get_signature_algorithm gnutls_x509_crt_get_signature_algorithm;
        pgnutls_x509_crt_get_signature gnutls_x509_crt_get_signature;
        pgnutls_x509_crt_get_version gnutls_x509_crt_get_version;
        pgnutls_x509_crt_get_pk_oid gnutls_x509_crt_get_pk_oid;
        pgnutls_x509_crt_get_signature_oid gnutls_x509_crt_get_signature_oid;
        pgnutls_x509_crt_get_key_id gnutls_x509_crt_get_key_id;
        pgnutls_x509_crt_set_private_key_usage_period gnutls_x509_crt_set_private_key_usage_period;
        pgnutls_x509_crt_set_authority_key_id gnutls_x509_crt_set_authority_key_id;
        pgnutls_x509_crt_get_authority_key_id gnutls_x509_crt_get_authority_key_id;
        pgnutls_x509_crt_get_authority_key_gn_serial gnutls_x509_crt_get_authority_key_gn_serial;
        pgnutls_x509_crt_get_subject_key_id gnutls_x509_crt_get_subject_key_id;
        pgnutls_x509_crt_get_subject_unique_id gnutls_x509_crt_get_subject_unique_id;
        pgnutls_x509_crt_get_issuer_unique_id gnutls_x509_crt_get_issuer_unique_id;
        pgnutls_x509_crt_set_pin_function gnutls_x509_crt_set_pin_function;
        pgnutls_x509_crt_get_authority_info_access gnutls_x509_crt_get_authority_info_access;
        pgnutls_x509_name_constraints_check gnutls_x509_name_constraints_check;
        pgnutls_x509_name_constraints_check_crt gnutls_x509_name_constraints_check_crt;
        pgnutls_x509_name_constraints_init gnutls_x509_name_constraints_init;
        pgnutls_x509_name_constraints_deinit gnutls_x509_name_constraints_deinit;
        pgnutls_x509_crt_get_name_constraints gnutls_x509_crt_get_name_constraints;
        pgnutls_x509_name_constraints_add_permitted gnutls_x509_name_constraints_add_permitted;
        pgnutls_x509_name_constraints_add_excluded gnutls_x509_name_constraints_add_excluded;
        pgnutls_x509_crt_set_name_constraints gnutls_x509_crt_set_name_constraints;
        pgnutls_x509_name_constraints_get_permitted gnutls_x509_name_constraints_get_permitted;
        pgnutls_x509_name_constraints_get_excluded gnutls_x509_name_constraints_get_excluded;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            pgnutls_x509_cidr_to_rfc5280 gnutls_x509_cidr_to_rfc5280;

        pgnutls_x509_crt_get_crl_dist_points gnutls_x509_crt_get_crl_dist_points;
        pgnutls_x509_crt_set_crl_dist_points2 gnutls_x509_crt_set_crl_dist_points2;
        pgnutls_x509_crt_set_crl_dist_points gnutls_x509_crt_set_crl_dist_points;
        pgnutls_x509_crt_cpy_crl_dist_points gnutls_x509_crt_cpy_crl_dist_points;
        pgnutls_x509_crl_sign gnutls_x509_crl_sign;
        pgnutls_x509_crl_sign2 gnutls_x509_crl_sign2;
        pgnutls_x509_crt_get_activation_time gnutls_x509_crt_get_activation_time;
        pgnutls_x509_crt_get_expiration_time gnutls_x509_crt_get_expiration_time;
        pgnutls_x509_crt_get_serial gnutls_x509_crt_get_serial;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_x509_spki_init gnutls_x509_spki_init;
            pgnutls_x509_spki_deinit gnutls_x509_spki_deinit;
        }

        pgnutls_x509_spki_get_rsa_pss_params gnutls_x509_spki_get_rsa_pss_params;
        pgnutls_x509_spki_set_rsa_pss_params gnutls_x509_spki_set_rsa_pss_params;
        pgnutls_x509_crt_get_pk_algorithm gnutls_x509_crt_get_pk_algorithm;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_x509_crt_set_spki gnutls_x509_crt_set_spki;
            pgnutls_x509_crt_get_spki gnutls_x509_crt_get_spki;
        }

        pgnutls_x509_crt_get_pk_rsa_raw gnutls_x509_crt_get_pk_rsa_raw;
        pgnutls_x509_crt_get_pk_dsa_raw gnutls_x509_crt_get_pk_dsa_raw;
        pgnutls_x509_crt_get_pk_ecc_raw gnutls_x509_crt_get_pk_ecc_raw;
        pgnutls_x509_crt_get_pk_gost_raw gnutls_x509_crt_get_pk_gost_raw;
        pgnutls_x509_crt_get_subject_alt_name gnutls_x509_crt_get_subject_alt_name;
        pgnutls_x509_crt_get_subject_alt_name2 gnutls_x509_crt_get_subject_alt_name2;
        pgnutls_x509_crt_get_subject_alt_othername_oid gnutls_x509_crt_get_subject_alt_othername_oid;
        pgnutls_x509_crt_get_issuer_alt_name gnutls_x509_crt_get_issuer_alt_name;
        pgnutls_x509_crt_get_issuer_alt_name2 gnutls_x509_crt_get_issuer_alt_name2;
        pgnutls_x509_crt_get_issuer_alt_othername_oid gnutls_x509_crt_get_issuer_alt_othername_oid;
        pgnutls_x509_crt_get_ca_status gnutls_x509_crt_get_ca_status;
        pgnutls_x509_crt_get_basic_constraints gnutls_x509_crt_get_basic_constraints;
        pgnutls_x509_crt_get_key_usage gnutls_x509_crt_get_key_usage;
        pgnutls_x509_crt_set_key_usage gnutls_x509_crt_set_key_usage;
        pgnutls_x509_crt_set_authority_info_access gnutls_x509_crt_set_authority_info_access;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_x509_crt_get_inhibit_anypolicy gnutls_x509_crt_get_inhibit_anypolicy;
            pgnutls_x509_crt_set_inhibit_anypolicy gnutls_x509_crt_set_inhibit_anypolicy;
        }

        pgnutls_x509_crt_get_proxy gnutls_x509_crt_get_proxy;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            pgnutls_x509_tlsfeatures_init gnutls_x509_tlsfeatures_init;
            pgnutls_x509_tlsfeatures_deinit gnutls_x509_tlsfeatures_deinit;
            pgnutls_x509_tlsfeatures_get gnutls_x509_tlsfeatures_get;
            pgnutls_x509_crt_set_tlsfeatures gnutls_x509_crt_set_tlsfeatures;
            pgnutls_x509_crt_get_tlsfeatures gnutls_x509_crt_get_tlsfeatures;
        }

        pgnutls_x509_tlsfeatures_check_crt gnutls_x509_tlsfeatures_check_crt;
        pgnutls_x509_policy_release gnutls_x509_policy_release;
        pgnutls_x509_crt_get_policy gnutls_x509_crt_get_policy;
        pgnutls_x509_crt_set_policy gnutls_x509_crt_set_policy;
        pgnutls_x509_dn_oid_known gnutls_x509_dn_oid_known;
        pgnutls_x509_dn_oid_name gnutls_x509_dn_oid_name;
        pgnutls_x509_crt_get_extension_oid gnutls_x509_crt_get_extension_oid;
        pgnutls_x509_crt_get_extension_by_oid gnutls_x509_crt_get_extension_by_oid;
        pgnutls_x509_crq_get_signature_algorithm gnutls_x509_crq_get_signature_algorithm;
        pgnutls_x509_crq_get_extension_by_oid2 gnutls_x509_crq_get_extension_by_oid2;
        pgnutls_x509_crt_get_extension_info gnutls_x509_crt_get_extension_info;
        pgnutls_x509_crt_get_extension_data gnutls_x509_crt_get_extension_data;
        pgnutls_x509_crt_get_extension_data2 gnutls_x509_crt_get_extension_data2;
        pgnutls_x509_crt_set_extension_by_oid gnutls_x509_crt_set_extension_by_oid;
        pgnutls_x509_crt_set_dn gnutls_x509_crt_set_dn;
        pgnutls_x509_crt_set_dn_by_oid gnutls_x509_crt_set_dn_by_oid;
        pgnutls_x509_crt_set_issuer_dn_by_oid gnutls_x509_crt_set_issuer_dn_by_oid;
        pgnutls_x509_crt_set_issuer_dn gnutls_x509_crt_set_issuer_dn;
        pgnutls_x509_crt_set_version gnutls_x509_crt_set_version;
        pgnutls_x509_crt_set_key gnutls_x509_crt_set_key;
        pgnutls_x509_crt_set_ca_status gnutls_x509_crt_set_ca_status;
        pgnutls_x509_crt_set_basic_constraints gnutls_x509_crt_set_basic_constraints;
        pgnutls_x509_crt_set_subject_unique_id gnutls_x509_crt_set_subject_unique_id;
        pgnutls_x509_crt_set_issuer_unique_id gnutls_x509_crt_set_issuer_unique_id;
        pgnutls_x509_crt_set_subject_alternative_name gnutls_x509_crt_set_subject_alternative_name;
        pgnutls_x509_crt_set_subject_alt_name gnutls_x509_crt_set_subject_alt_name;
        pgnutls_x509_crt_set_subject_alt_othername gnutls_x509_crt_set_subject_alt_othername;
        pgnutls_x509_crt_set_issuer_alt_name gnutls_x509_crt_set_issuer_alt_name;
        pgnutls_x509_crt_set_issuer_alt_othername gnutls_x509_crt_set_issuer_alt_othername;
        pgnutls_x509_crt_sign gnutls_x509_crt_sign;
        pgnutls_x509_crt_sign2 gnutls_x509_crt_sign2;
        pgnutls_x509_crt_set_activation_time gnutls_x509_crt_set_activation_time;
        pgnutls_x509_crt_set_expiration_time gnutls_x509_crt_set_expiration_time;
        pgnutls_x509_crt_set_serial gnutls_x509_crt_set_serial;
        pgnutls_x509_crt_set_subject_key_id gnutls_x509_crt_set_subject_key_id;
        pgnutls_x509_crt_set_proxy_dn gnutls_x509_crt_set_proxy_dn;
        pgnutls_x509_crt_set_proxy gnutls_x509_crt_set_proxy;
        pgnutls_x509_crt_print gnutls_x509_crt_print;
        pgnutls_x509_crl_print gnutls_x509_crl_print;
        pgnutls_x509_crt_get_raw_issuer_dn gnutls_x509_crt_get_raw_issuer_dn;
        pgnutls_x509_crt_get_raw_dn gnutls_x509_crt_get_raw_dn;
        pgnutls_x509_rdn_get gnutls_x509_rdn_get;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_rdn_get2 gnutls_x509_rdn_get2;

        pgnutls_x509_rdn_get_oid gnutls_x509_rdn_get_oid;
        pgnutls_x509_rdn_get_by_oid gnutls_x509_rdn_get_by_oid;
        pgnutls_x509_crt_get_subject gnutls_x509_crt_get_subject;
        pgnutls_x509_crt_get_issuer gnutls_x509_crt_get_issuer;
        pgnutls_x509_dn_get_rdn_ava gnutls_x509_dn_get_rdn_ava;
        pgnutls_x509_dn_get_str gnutls_x509_dn_get_str;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_dn_get_str2 gnutls_x509_dn_get_str2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            pgnutls_x509_dn_set_str gnutls_x509_dn_set_str;

        pgnutls_x509_dn_init gnutls_x509_dn_init;
        pgnutls_x509_dn_import gnutls_x509_dn_import;
        pgnutls_x509_dn_export gnutls_x509_dn_export;
        pgnutls_x509_dn_export2 gnutls_x509_dn_export2;
        pgnutls_x509_dn_deinit gnutls_x509_dn_deinit;
        pgnutls_x509_crl_init gnutls_x509_crl_init;
        pgnutls_x509_crl_deinit gnutls_x509_crl_deinit;
        pgnutls_x509_crl_import gnutls_x509_crl_import;
        pgnutls_x509_crl_export gnutls_x509_crl_export;
        pgnutls_x509_crl_export2 gnutls_x509_crl_export2;
        pgnutls_x509_crl_get_raw_issuer_dn gnutls_x509_crl_get_raw_issuer_dn;
        pgnutls_x509_crl_get_issuer_dn gnutls_x509_crl_get_issuer_dn;
        pgnutls_x509_crl_get_issuer_dn2 gnutls_x509_crl_get_issuer_dn2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_crl_get_issuer_dn3 gnutls_x509_crl_get_issuer_dn3;

        pgnutls_x509_crl_get_issuer_dn_by_oid gnutls_x509_crl_get_issuer_dn_by_oid;
        pgnutls_x509_crl_get_dn_oid gnutls_x509_crl_get_dn_oid;
        pgnutls_x509_crl_get_signature_algorithm gnutls_x509_crl_get_signature_algorithm;
        pgnutls_x509_crl_get_signature gnutls_x509_crl_get_signature;
        pgnutls_x509_crl_get_version gnutls_x509_crl_get_version;
        pgnutls_x509_crl_get_signature_oid gnutls_x509_crl_get_signature_oid;
        pgnutls_x509_crl_get_this_update gnutls_x509_crl_get_this_update;
        pgnutls_x509_crl_get_next_update gnutls_x509_crl_get_next_update;
        pgnutls_x509_crl_get_crt_count gnutls_x509_crl_get_crt_count;
        pgnutls_x509_crl_get_crt_serial gnutls_x509_crl_get_crt_serial;
        pgnutls_x509_crl_iter_crt_serial gnutls_x509_crl_iter_crt_serial;
        pgnutls_x509_crl_iter_deinit gnutls_x509_crl_iter_deinit;
        pgnutls_x509_crl_check_issuer gnutls_x509_crl_check_issuer;
        pgnutls_x509_crl_list_import2 gnutls_x509_crl_list_import2;
        pgnutls_x509_crl_list_import gnutls_x509_crl_list_import;
        pgnutls_x509_crl_set_version gnutls_x509_crl_set_version;
        pgnutls_x509_crl_set_this_update gnutls_x509_crl_set_this_update;
        pgnutls_x509_crl_set_next_update gnutls_x509_crl_set_next_update;
        pgnutls_x509_crl_set_crt_serial gnutls_x509_crl_set_crt_serial;
        pgnutls_x509_crl_set_crt gnutls_x509_crl_set_crt;
        pgnutls_x509_crl_get_authority_key_id gnutls_x509_crl_get_authority_key_id;
        pgnutls_x509_crl_get_authority_key_gn_serial gnutls_x509_crl_get_authority_key_gn_serial;
        pgnutls_x509_crl_get_number gnutls_x509_crl_get_number;
        pgnutls_x509_crl_get_extension_oid gnutls_x509_crl_get_extension_oid;
        pgnutls_x509_crl_get_extension_info gnutls_x509_crl_get_extension_info;
        pgnutls_x509_crl_get_extension_data gnutls_x509_crl_get_extension_data;
        pgnutls_x509_crl_get_extension_data2 gnutls_x509_crl_get_extension_data2;
        pgnutls_x509_crl_set_authority_key_id gnutls_x509_crl_set_authority_key_id;
        pgnutls_x509_crl_set_number gnutls_x509_crl_set_number;
        pgnutls_certificate_verification_profile_get_name gnutls_certificate_verification_profile_get_name;
        pgnutls_certificate_verification_profile_get_id gnutls_certificate_verification_profile_get_id;
        pgnutls_x509_crt_check_issuer gnutls_x509_crt_check_issuer;
        pgnutls_x509_crt_list_verify gnutls_x509_crt_list_verify;
        pgnutls_x509_crt_verify gnutls_x509_crt_verify;
        pgnutls_x509_crl_verify gnutls_x509_crl_verify;
        pgnutls_x509_crt_verify_data2 gnutls_x509_crt_verify_data2;
        pgnutls_x509_crt_check_revocation gnutls_x509_crt_check_revocation;
        pgnutls_x509_crt_get_fingerprint gnutls_x509_crt_get_fingerprint;
        pgnutls_x509_crt_get_key_purpose_oid gnutls_x509_crt_get_key_purpose_oid;
        pgnutls_x509_crt_set_key_purpose_oid gnutls_x509_crt_set_key_purpose_oid;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            pgnutls_x509_crt_check_key_purpose gnutls_x509_crt_check_key_purpose;

        pgnutls_pkcs_schema_get_name gnutls_pkcs_schema_get_name;
        pgnutls_pkcs_schema_get_oid gnutls_pkcs_schema_get_oid;
        pgnutls_x509_privkey_init gnutls_x509_privkey_init;
        pgnutls_x509_privkey_deinit gnutls_x509_privkey_deinit;
        pgnutls_x509_privkey_sec_param gnutls_x509_privkey_sec_param;
        pgnutls_x509_privkey_set_pin_function gnutls_x509_privkey_set_pin_function;
        pgnutls_x509_privkey_cpy gnutls_x509_privkey_cpy;
        pgnutls_x509_privkey_import gnutls_x509_privkey_import;
        pgnutls_x509_privkey_import_pkcs8 gnutls_x509_privkey_import_pkcs8;
        pgnutls_x509_privkey_import_openssl gnutls_x509_privkey_import_openssl;
        pgnutls_pkcs8_info gnutls_pkcs8_info;
        pgnutls_x509_privkey_import2 gnutls_x509_privkey_import2;
        pgnutls_x509_privkey_import_rsa_raw gnutls_x509_privkey_import_rsa_raw;
        pgnutls_x509_privkey_import_rsa_raw2 gnutls_x509_privkey_import_rsa_raw2;
        pgnutls_x509_privkey_import_ecc_raw gnutls_x509_privkey_import_ecc_raw;
        pgnutls_x509_privkey_import_gost_raw gnutls_x509_privkey_import_gost_raw;
        pgnutls_x509_privkey_fix gnutls_x509_privkey_fix;
        pgnutls_x509_privkey_export_dsa_raw gnutls_x509_privkey_export_dsa_raw;
        pgnutls_x509_privkey_import_dsa_raw gnutls_x509_privkey_import_dsa_raw;
        pgnutls_x509_privkey_get_pk_algorithm gnutls_x509_privkey_get_pk_algorithm;
        pgnutls_x509_privkey_get_pk_algorithm2 gnutls_x509_privkey_get_pk_algorithm2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_x509_privkey_get_spki gnutls_x509_privkey_get_spki;
            pgnutls_x509_privkey_set_spki gnutls_x509_privkey_set_spki;
        }

        pgnutls_x509_privkey_get_key_id gnutls_x509_privkey_get_key_id;
        pgnutls_x509_privkey_generate gnutls_x509_privkey_generate;
        pgnutls_x509_privkey_set_flags gnutls_x509_privkey_set_flags;
        pgnutls_x509_privkey_generate2 gnutls_x509_privkey_generate2;
        pgnutls_x509_privkey_verify_seed gnutls_x509_privkey_verify_seed;
        pgnutls_x509_privkey_get_seed gnutls_x509_privkey_get_seed;
        pgnutls_x509_privkey_verify_params gnutls_x509_privkey_verify_params;
        pgnutls_x509_privkey_export gnutls_x509_privkey_export;
        pgnutls_x509_privkey_export2 gnutls_x509_privkey_export2;
        pgnutls_x509_privkey_export_pkcs8 gnutls_x509_privkey_export_pkcs8;
        pgnutls_x509_privkey_export2_pkcs8 gnutls_x509_privkey_export2_pkcs8;
        pgnutls_x509_privkey_export_rsa_raw2 gnutls_x509_privkey_export_rsa_raw2;
        pgnutls_x509_privkey_export_rsa_raw gnutls_x509_privkey_export_rsa_raw;
        pgnutls_x509_privkey_export_ecc_raw gnutls_x509_privkey_export_ecc_raw;
        pgnutls_x509_privkey_export_gost_raw gnutls_x509_privkey_export_gost_raw;
        pgnutls_x509_privkey_sign_data gnutls_x509_privkey_sign_data;
        pgnutls_x509_crq_sign gnutls_x509_crq_sign;
        pgnutls_x509_crq_sign2 gnutls_x509_crq_sign2;
        pgnutls_x509_crq_print gnutls_x509_crq_print;
        pgnutls_x509_crq_verify gnutls_x509_crq_verify;
        pgnutls_x509_crq_init gnutls_x509_crq_init;
        pgnutls_x509_crq_deinit gnutls_x509_crq_deinit;
        pgnutls_x509_crq_import gnutls_x509_crq_import;
        pgnutls_x509_crq_get_private_key_usage_period gnutls_x509_crq_get_private_key_usage_period;
        pgnutls_x509_crq_get_dn gnutls_x509_crq_get_dn;
        pgnutls_x509_crq_get_dn2 gnutls_x509_crq_get_dn2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_x509_crq_get_dn3 gnutls_x509_crq_get_dn3;

        pgnutls_x509_crq_get_dn_oid gnutls_x509_crq_get_dn_oid;
        pgnutls_x509_crq_get_dn_by_oid gnutls_x509_crq_get_dn_by_oid;
        pgnutls_x509_crq_set_dn gnutls_x509_crq_set_dn;
        pgnutls_x509_crq_set_dn_by_oid gnutls_x509_crq_set_dn_by_oid;
        pgnutls_x509_crq_set_version gnutls_x509_crq_set_version;
        pgnutls_x509_crq_get_version gnutls_x509_crq_get_version;
        pgnutls_x509_crq_set_key gnutls_x509_crq_set_key;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            pgnutls_x509_crq_set_extension_by_oid gnutls_x509_crq_set_extension_by_oid;

        pgnutls_x509_crq_set_challenge_password gnutls_x509_crq_set_challenge_password;
        pgnutls_x509_crq_get_challenge_password gnutls_x509_crq_get_challenge_password;
        pgnutls_x509_crq_set_attribute_by_oid gnutls_x509_crq_set_attribute_by_oid;
        pgnutls_x509_crq_get_attribute_by_oid gnutls_x509_crq_get_attribute_by_oid;
        pgnutls_x509_crq_export gnutls_x509_crq_export;
        pgnutls_x509_crq_export2 gnutls_x509_crq_export2;
        pgnutls_x509_crt_set_crq gnutls_x509_crt_set_crq;
        pgnutls_x509_crt_set_crq_extensions gnutls_x509_crt_set_crq_extensions;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            pgnutls_x509_crt_set_crq_extension_by_oid gnutls_x509_crt_set_crq_extension_by_oid;

        pgnutls_x509_crq_set_private_key_usage_period gnutls_x509_crq_set_private_key_usage_period;
        pgnutls_x509_crq_set_key_rsa_raw gnutls_x509_crq_set_key_rsa_raw;
        pgnutls_x509_crq_set_subject_alt_name gnutls_x509_crq_set_subject_alt_name;
        pgnutls_x509_crq_set_subject_alt_othername gnutls_x509_crq_set_subject_alt_othername;
        pgnutls_x509_crq_set_key_usage gnutls_x509_crq_set_key_usage;
        pgnutls_x509_crq_set_basic_constraints gnutls_x509_crq_set_basic_constraints;
        pgnutls_x509_crq_set_key_purpose_oid gnutls_x509_crq_set_key_purpose_oid;
        pgnutls_x509_crq_get_key_purpose_oid gnutls_x509_crq_get_key_purpose_oid;
        pgnutls_x509_crq_get_extension_data gnutls_x509_crq_get_extension_data;
        pgnutls_x509_crq_get_extension_data2 gnutls_x509_crq_get_extension_data2;
        pgnutls_x509_crq_get_extension_info gnutls_x509_crq_get_extension_info;
        pgnutls_x509_crq_get_attribute_data gnutls_x509_crq_get_attribute_data;
        pgnutls_x509_crq_get_attribute_info gnutls_x509_crq_get_attribute_info;
        pgnutls_x509_crq_get_pk_algorithm gnutls_x509_crq_get_pk_algorithm;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_x509_crq_get_spki gnutls_x509_crq_get_spki;
            pgnutls_x509_crq_set_spki gnutls_x509_crq_set_spki;
        }

        pgnutls_x509_crq_get_signature_oid gnutls_x509_crq_get_signature_oid;
        pgnutls_x509_crq_get_pk_oid gnutls_x509_crq_get_pk_oid;
        pgnutls_x509_crq_get_key_id gnutls_x509_crq_get_key_id;
        pgnutls_x509_crq_get_key_rsa_raw gnutls_x509_crq_get_key_rsa_raw;
        pgnutls_x509_crq_get_key_usage gnutls_x509_crq_get_key_usage;
        pgnutls_x509_crq_get_basic_constraints gnutls_x509_crq_get_basic_constraints;
        pgnutls_x509_crq_get_subject_alt_name gnutls_x509_crq_get_subject_alt_name;
        pgnutls_x509_crq_get_subject_alt_othername_oid gnutls_x509_crq_get_subject_alt_othername_oid;
        pgnutls_x509_crq_get_extension_by_oid gnutls_x509_crq_get_extension_by_oid;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            pgnutls_x509_crq_get_tlsfeatures gnutls_x509_crq_get_tlsfeatures;
            pgnutls_x509_crq_set_tlsfeatures gnutls_x509_crq_set_tlsfeatures;
        }

        pgnutls_x509_crt_get_extension_by_oid2 gnutls_x509_crt_get_extension_by_oid2;
        pgnutls_x509_trust_list_init gnutls_x509_trust_list_init;
        pgnutls_x509_trust_list_deinit gnutls_x509_trust_list_deinit;
        pgnutls_x509_trust_list_get_issuer gnutls_x509_trust_list_get_issuer;
        pgnutls_x509_trust_list_get_issuer_by_dn gnutls_x509_trust_list_get_issuer_by_dn;
        pgnutls_x509_trust_list_get_issuer_by_subject_key_id gnutls_x509_trust_list_get_issuer_by_subject_key_id;
        pgnutls_x509_trust_list_add_cas gnutls_x509_trust_list_add_cas;
        pgnutls_x509_trust_list_remove_cas gnutls_x509_trust_list_remove_cas;
        pgnutls_x509_trust_list_add_named_crt gnutls_x509_trust_list_add_named_crt;
        pgnutls_x509_trust_list_add_crls gnutls_x509_trust_list_add_crls;
        pgnutls_x509_trust_list_iter_get_ca gnutls_x509_trust_list_iter_get_ca;
        pgnutls_x509_trust_list_iter_deinit gnutls_x509_trust_list_iter_deinit;
        pgnutls_x509_trust_list_verify_named_crt gnutls_x509_trust_list_verify_named_crt;
        pgnutls_x509_trust_list_verify_crt2 gnutls_x509_trust_list_verify_crt2;
        pgnutls_x509_trust_list_verify_crt gnutls_x509_trust_list_verify_crt;
        pgnutls_x509_trust_list_add_trust_mem gnutls_x509_trust_list_add_trust_mem;
        pgnutls_x509_trust_list_add_trust_file gnutls_x509_trust_list_add_trust_file;
        pgnutls_x509_trust_list_add_trust_dir gnutls_x509_trust_list_add_trust_dir;
        pgnutls_x509_trust_list_remove_trust_file gnutls_x509_trust_list_remove_trust_file;
        pgnutls_x509_trust_list_remove_trust_mem gnutls_x509_trust_list_remove_trust_mem;
        pgnutls_x509_trust_list_add_system_trust gnutls_x509_trust_list_add_system_trust;
        pgnutls_certificate_set_trust_list gnutls_certificate_set_trust_list;
        pgnutls_certificate_get_trust_list gnutls_certificate_get_trust_list;
        pgnutls_x509_ext_deinit gnutls_x509_ext_deinit;
        pgnutls_x509_ext_print gnutls_x509_ext_print;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindX509(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_x509_crt_init, "gnutls_x509_crt_init");
        lib.bindSymbol_stdcall(gnutls_x509_crt_deinit, "gnutls_x509_crt_deinit");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            lib.bindSymbol_stdcall(gnutls_x509_crt_set_flags, "gnutls_x509_crt_set_flags");

        lib.bindSymbol_stdcall(gnutls_x509_crt_equals, "gnutls_x509_crt_equals");
        lib.bindSymbol_stdcall(gnutls_x509_crt_equals2, "gnutls_x509_crt_equals2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_import, "gnutls_x509_crt_import");
        lib.bindSymbol_stdcall(gnutls_x509_crt_list_import2, "gnutls_x509_crt_list_import2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_list_import, "gnutls_x509_crt_list_import");
        lib.bindSymbol_stdcall(gnutls_x509_crt_import_url, "gnutls_x509_crt_import_url");
        lib.bindSymbol_stdcall(gnutls_x509_crt_list_import_url, "gnutls_x509_crt_list_import_url");
        lib.bindSymbol_stdcall(gnutls_x509_crt_export, "gnutls_x509_crt_export");
        lib.bindSymbol_stdcall(gnutls_x509_crt_export2, "gnutls_x509_crt_export2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_private_key_usage_period, "gnutls_x509_crt_get_private_key_usage_period");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_dn, "gnutls_x509_crt_get_issuer_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_dn2, "gnutls_x509_crt_get_issuer_dn2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_dn3, "gnutls_x509_crt_get_issuer_dn3");

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_dn_oid, "gnutls_x509_crt_get_issuer_dn_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_dn_by_oid, "gnutls_x509_crt_get_issuer_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_dn, "gnutls_x509_crt_get_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_dn2, "gnutls_x509_crt_get_dn2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_crt_get_dn3, "gnutls_x509_crt_get_dn3");

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_dn_oid, "gnutls_x509_crt_get_dn_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_dn_by_oid, "gnutls_x509_crt_get_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_check_hostname, "gnutls_x509_crt_check_hostname");
        lib.bindSymbol_stdcall(gnutls_x509_crt_check_hostname2, "gnutls_x509_crt_check_hostname2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_check_email, "gnutls_x509_crt_check_email");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
            lib.bindSymbol_stdcall(gnutls_x509_crt_check_ip, "gnutls_x509_crt_check_ip");

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_signature_algorithm, "gnutls_x509_crt_get_signature_algorithm");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_signature, "gnutls_x509_crt_get_signature");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_version, "gnutls_x509_crt_get_version");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_oid, "gnutls_x509_crt_get_pk_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_signature_oid, "gnutls_x509_crt_get_signature_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_key_id, "gnutls_x509_crt_get_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_private_key_usage_period, "gnutls_x509_crt_set_private_key_usage_period");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_authority_key_id, "gnutls_x509_crt_set_authority_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_authority_key_id, "gnutls_x509_crt_get_authority_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_authority_key_gn_serial, "gnutls_x509_crt_get_authority_key_gn_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject_key_id, "gnutls_x509_crt_get_subject_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject_unique_id, "gnutls_x509_crt_get_subject_unique_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_unique_id, "gnutls_x509_crt_get_issuer_unique_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_pin_function, "gnutls_x509_crt_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_authority_info_access, "gnutls_x509_crt_get_authority_info_access");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_check, "gnutls_x509_name_constraints_check");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_check_crt, "gnutls_x509_name_constraints_check_crt");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_init, "gnutls_x509_name_constraints_init");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_deinit, "gnutls_x509_name_constraints_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_name_constraints, "gnutls_x509_crt_get_name_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_add_permitted, "gnutls_x509_name_constraints_add_permitted");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_add_excluded, "gnutls_x509_name_constraints_add_excluded");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_name_constraints, "gnutls_x509_crt_set_name_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_get_permitted, "gnutls_x509_name_constraints_get_permitted");
        lib.bindSymbol_stdcall(gnutls_x509_name_constraints_get_excluded, "gnutls_x509_name_constraints_get_excluded");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            lib.bindSymbol_stdcall(gnutls_x509_cidr_to_rfc5280, "gnutls_x509_cidr_to_rfc5280");

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_crl_dist_points, "gnutls_x509_crt_get_crl_dist_points");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_crl_dist_points2, "gnutls_x509_crt_set_crl_dist_points2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_crl_dist_points, "gnutls_x509_crt_set_crl_dist_points");
        lib.bindSymbol_stdcall(gnutls_x509_crt_cpy_crl_dist_points, "gnutls_x509_crt_cpy_crl_dist_points");
        lib.bindSymbol_stdcall(gnutls_x509_crl_sign, "gnutls_x509_crl_sign");
        lib.bindSymbol_stdcall(gnutls_x509_crl_sign2, "gnutls_x509_crl_sign2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_activation_time, "gnutls_x509_crt_get_activation_time");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_expiration_time, "gnutls_x509_crt_get_expiration_time");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_serial, "gnutls_x509_crt_get_serial");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_x509_spki_init, "gnutls_x509_spki_init");
            lib.bindSymbol_stdcall(gnutls_x509_spki_deinit, "gnutls_x509_spki_deinit");
        }

        lib.bindSymbol_stdcall(gnutls_x509_spki_get_rsa_pss_params, "gnutls_x509_spki_get_rsa_pss_params");
        lib.bindSymbol_stdcall(gnutls_x509_spki_set_rsa_pss_params, "gnutls_x509_spki_set_rsa_pss_params");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_algorithm, "gnutls_x509_crt_get_pk_algorithm");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_x509_crt_set_spki, "gnutls_x509_crt_set_spki");
            lib.bindSymbol_stdcall(gnutls_x509_crt_get_spki, "gnutls_x509_crt_get_spki");
        }

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_rsa_raw, "gnutls_x509_crt_get_pk_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_dsa_raw, "gnutls_x509_crt_get_pk_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_ecc_raw, "gnutls_x509_crt_get_pk_ecc_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_pk_gost_raw, "gnutls_x509_crt_get_pk_gost_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject_alt_name, "gnutls_x509_crt_get_subject_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject_alt_name2, "gnutls_x509_crt_get_subject_alt_name2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject_alt_othername_oid, "gnutls_x509_crt_get_subject_alt_othername_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_alt_name, "gnutls_x509_crt_get_issuer_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_alt_name2, "gnutls_x509_crt_get_issuer_alt_name2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer_alt_othername_oid, "gnutls_x509_crt_get_issuer_alt_othername_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_ca_status, "gnutls_x509_crt_get_ca_status");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_basic_constraints, "gnutls_x509_crt_get_basic_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_key_usage, "gnutls_x509_crt_get_key_usage");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_key_usage, "gnutls_x509_crt_set_key_usage");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_authority_info_access, "gnutls_x509_crt_set_authority_info_access");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_x509_crt_get_inhibit_anypolicy, "gnutls_x509_crt_get_inhibit_anypolicy");
            lib.bindSymbol_stdcall(gnutls_x509_crt_set_inhibit_anypolicy, "gnutls_x509_crt_set_inhibit_anypolicy");
        }

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_proxy, "gnutls_x509_crt_get_proxy");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            lib.bindSymbol_stdcall(gnutls_x509_tlsfeatures_init, "gnutls_x509_tlsfeatures_init");
            lib.bindSymbol_stdcall(gnutls_x509_tlsfeatures_deinit, "gnutls_x509_tlsfeatures_deinit");
            lib.bindSymbol_stdcall(gnutls_x509_tlsfeatures_get, "gnutls_x509_tlsfeatures_get");
            lib.bindSymbol_stdcall(gnutls_x509_crt_set_tlsfeatures, "gnutls_x509_crt_set_tlsfeatures");
            lib.bindSymbol_stdcall(gnutls_x509_crt_get_tlsfeatures, "gnutls_x509_crt_get_tlsfeatures");
        }

        lib.bindSymbol_stdcall(gnutls_x509_tlsfeatures_check_crt, "gnutls_x509_tlsfeatures_check_crt");
        lib.bindSymbol_stdcall(gnutls_x509_policy_release, "gnutls_x509_policy_release");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_policy, "gnutls_x509_crt_get_policy");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_policy, "gnutls_x509_crt_set_policy");
        lib.bindSymbol_stdcall(gnutls_x509_dn_oid_known, "gnutls_x509_dn_oid_known");
        lib.bindSymbol_stdcall(gnutls_x509_dn_oid_name, "gnutls_x509_dn_oid_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_oid, "gnutls_x509_crt_get_extension_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_by_oid, "gnutls_x509_crt_get_extension_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_signature_algorithm, "gnutls_x509_crq_get_signature_algorithm");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_extension_by_oid2, "gnutls_x509_crq_get_extension_by_oid2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_info, "gnutls_x509_crt_get_extension_info");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_data, "gnutls_x509_crt_get_extension_data");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_data2, "gnutls_x509_crt_get_extension_data2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_extension_by_oid, "gnutls_x509_crt_set_extension_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_dn, "gnutls_x509_crt_set_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_dn_by_oid, "gnutls_x509_crt_set_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_issuer_dn_by_oid, "gnutls_x509_crt_set_issuer_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_issuer_dn, "gnutls_x509_crt_set_issuer_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_version, "gnutls_x509_crt_set_version");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_key, "gnutls_x509_crt_set_key");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_ca_status, "gnutls_x509_crt_set_ca_status");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_basic_constraints, "gnutls_x509_crt_set_basic_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_subject_unique_id, "gnutls_x509_crt_set_subject_unique_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_issuer_unique_id, "gnutls_x509_crt_set_issuer_unique_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_subject_alternative_name, "gnutls_x509_crt_set_subject_alternative_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_subject_alt_name, "gnutls_x509_crt_set_subject_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_subject_alt_othername, "gnutls_x509_crt_set_subject_alt_othername");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_issuer_alt_name, "gnutls_x509_crt_set_issuer_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_issuer_alt_othername, "gnutls_x509_crt_set_issuer_alt_othername");
        lib.bindSymbol_stdcall(gnutls_x509_crt_sign, "gnutls_x509_crt_sign");
        lib.bindSymbol_stdcall(gnutls_x509_crt_sign2, "gnutls_x509_crt_sign2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_activation_time, "gnutls_x509_crt_set_activation_time");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_expiration_time, "gnutls_x509_crt_set_expiration_time");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_serial, "gnutls_x509_crt_set_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_subject_key_id, "gnutls_x509_crt_set_subject_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_proxy_dn, "gnutls_x509_crt_set_proxy_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_proxy, "gnutls_x509_crt_set_proxy");
        lib.bindSymbol_stdcall(gnutls_x509_crt_print, "gnutls_x509_crt_print");
        lib.bindSymbol_stdcall(gnutls_x509_crl_print, "gnutls_x509_crl_print");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_raw_issuer_dn, "gnutls_x509_crt_get_raw_issuer_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_raw_dn, "gnutls_x509_crt_get_raw_dn");
        lib.bindSymbol_stdcall(gnutls_x509_rdn_get, "gnutls_x509_rdn_get");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_rdn_get2, "gnutls_x509_rdn_get2");

        lib.bindSymbol_stdcall(gnutls_x509_rdn_get_oid, "gnutls_x509_rdn_get_oid");
        lib.bindSymbol_stdcall(gnutls_x509_rdn_get_by_oid, "gnutls_x509_rdn_get_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_subject, "gnutls_x509_crt_get_subject");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_issuer, "gnutls_x509_crt_get_issuer");
        lib.bindSymbol_stdcall(gnutls_x509_dn_get_rdn_ava, "gnutls_x509_dn_get_rdn_ava");
        lib.bindSymbol_stdcall(gnutls_x509_dn_get_str, "gnutls_x509_dn_get_str");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_dn_get_str2, "gnutls_x509_dn_get_str2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            lib.bindSymbol_stdcall(gnutls_x509_dn_set_str, "gnutls_x509_dn_set_str");

        lib.bindSymbol_stdcall(gnutls_x509_dn_init, "gnutls_x509_dn_init");
        lib.bindSymbol_stdcall(gnutls_x509_dn_import, "gnutls_x509_dn_import");
        lib.bindSymbol_stdcall(gnutls_x509_dn_export, "gnutls_x509_dn_export");
        lib.bindSymbol_stdcall(gnutls_x509_dn_export2, "gnutls_x509_dn_export2");
        lib.bindSymbol_stdcall(gnutls_x509_dn_deinit, "gnutls_x509_dn_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_crl_init, "gnutls_x509_crl_init");
        lib.bindSymbol_stdcall(gnutls_x509_crl_deinit, "gnutls_x509_crl_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_crl_import, "gnutls_x509_crl_import");
        lib.bindSymbol_stdcall(gnutls_x509_crl_export, "gnutls_x509_crl_export");
        lib.bindSymbol_stdcall(gnutls_x509_crl_export2, "gnutls_x509_crl_export2");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_raw_issuer_dn, "gnutls_x509_crl_get_raw_issuer_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_issuer_dn, "gnutls_x509_crl_get_issuer_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_issuer_dn2, "gnutls_x509_crl_get_issuer_dn2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_crl_get_issuer_dn3, "gnutls_x509_crl_get_issuer_dn3");

        lib.bindSymbol_stdcall(gnutls_x509_crl_get_issuer_dn_by_oid, "gnutls_x509_crl_get_issuer_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_dn_oid, "gnutls_x509_crl_get_dn_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_signature_algorithm, "gnutls_x509_crl_get_signature_algorithm");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_signature, "gnutls_x509_crl_get_signature");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_version, "gnutls_x509_crl_get_version");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_signature_oid, "gnutls_x509_crl_get_signature_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_this_update, "gnutls_x509_crl_get_this_update");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_next_update, "gnutls_x509_crl_get_next_update");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_crt_count, "gnutls_x509_crl_get_crt_count");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_crt_serial, "gnutls_x509_crl_get_crt_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crl_iter_crt_serial, "gnutls_x509_crl_iter_crt_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crl_iter_deinit, "gnutls_x509_crl_iter_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_crl_check_issuer, "gnutls_x509_crl_check_issuer");
        lib.bindSymbol_stdcall(gnutls_x509_crl_list_import2, "gnutls_x509_crl_list_import2");
        lib.bindSymbol_stdcall(gnutls_x509_crl_list_import, "gnutls_x509_crl_list_import");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_version, "gnutls_x509_crl_set_version");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_this_update, "gnutls_x509_crl_set_this_update");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_next_update, "gnutls_x509_crl_set_next_update");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_crt_serial, "gnutls_x509_crl_set_crt_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_crt, "gnutls_x509_crl_set_crt");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_authority_key_id, "gnutls_x509_crl_get_authority_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_authority_key_gn_serial, "gnutls_x509_crl_get_authority_key_gn_serial");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_number, "gnutls_x509_crl_get_number");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_extension_oid, "gnutls_x509_crl_get_extension_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_extension_info, "gnutls_x509_crl_get_extension_info");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_extension_data, "gnutls_x509_crl_get_extension_data");
        lib.bindSymbol_stdcall(gnutls_x509_crl_get_extension_data2, "gnutls_x509_crl_get_extension_data2");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_authority_key_id, "gnutls_x509_crl_set_authority_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crl_set_number, "gnutls_x509_crl_set_number");
        lib.bindSymbol_stdcall(gnutls_certificate_verification_profile_get_name, "gnutls_certificate_verification_profile_get_name");
        lib.bindSymbol_stdcall(gnutls_certificate_verification_profile_get_id, "gnutls_certificate_verification_profile_get_id");
        lib.bindSymbol_stdcall(gnutls_x509_crt_check_issuer, "gnutls_x509_crt_check_issuer");
        lib.bindSymbol_stdcall(gnutls_x509_crt_list_verify, "gnutls_x509_crt_list_verify");
        lib.bindSymbol_stdcall(gnutls_x509_crt_verify, "gnutls_x509_crt_verify");
        lib.bindSymbol_stdcall(gnutls_x509_crl_verify, "gnutls_x509_crl_verify");
        lib.bindSymbol_stdcall(gnutls_x509_crt_verify_data2, "gnutls_x509_crt_verify_data2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_check_revocation, "gnutls_x509_crt_check_revocation");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_fingerprint, "gnutls_x509_crt_get_fingerprint");
        lib.bindSymbol_stdcall(gnutls_x509_crt_get_key_purpose_oid, "gnutls_x509_crt_get_key_purpose_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_key_purpose_oid, "gnutls_x509_crt_set_key_purpose_oid");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            lib.bindSymbol_stdcall(gnutls_x509_crt_check_key_purpose, "gnutls_x509_crt_check_key_purpose");

        lib.bindSymbol_stdcall(gnutls_pkcs_schema_get_name, "gnutls_pkcs_schema_get_name");
        lib.bindSymbol_stdcall(gnutls_pkcs_schema_get_oid, "gnutls_pkcs_schema_get_oid");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_init, "gnutls_x509_privkey_init");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_deinit, "gnutls_x509_privkey_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_sec_param, "gnutls_x509_privkey_sec_param");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_set_pin_function, "gnutls_x509_privkey_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_cpy, "gnutls_x509_privkey_cpy");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import, "gnutls_x509_privkey_import");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_pkcs8, "gnutls_x509_privkey_import_pkcs8");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_openssl, "gnutls_x509_privkey_import_openssl");
        lib.bindSymbol_stdcall(gnutls_pkcs8_info, "gnutls_pkcs8_info");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import2, "gnutls_x509_privkey_import2");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_rsa_raw, "gnutls_x509_privkey_import_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_rsa_raw2, "gnutls_x509_privkey_import_rsa_raw2");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_ecc_raw, "gnutls_x509_privkey_import_ecc_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_gost_raw, "gnutls_x509_privkey_import_gost_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_fix, "gnutls_x509_privkey_fix");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_dsa_raw, "gnutls_x509_privkey_export_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_import_dsa_raw, "gnutls_x509_privkey_import_dsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_get_pk_algorithm, "gnutls_x509_privkey_get_pk_algorithm");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_get_pk_algorithm2, "gnutls_x509_privkey_get_pk_algorithm2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_x509_privkey_get_spki, "gnutls_x509_privkey_get_spki");
            lib.bindSymbol_stdcall(gnutls_x509_privkey_set_spki, "gnutls_x509_privkey_set_spki");
        }

        lib.bindSymbol_stdcall(gnutls_x509_privkey_get_key_id, "gnutls_x509_privkey_get_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_generate, "gnutls_x509_privkey_generate");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_set_flags, "gnutls_x509_privkey_set_flags");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_generate2, "gnutls_x509_privkey_generate2");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_verify_seed, "gnutls_x509_privkey_verify_seed");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_get_seed, "gnutls_x509_privkey_get_seed");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_verify_params, "gnutls_x509_privkey_verify_params");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export, "gnutls_x509_privkey_export");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export2, "gnutls_x509_privkey_export2");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_pkcs8, "gnutls_x509_privkey_export_pkcs8");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export2_pkcs8, "gnutls_x509_privkey_export2_pkcs8");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_rsa_raw2, "gnutls_x509_privkey_export_rsa_raw2");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_rsa_raw, "gnutls_x509_privkey_export_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_ecc_raw, "gnutls_x509_privkey_export_ecc_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_export_gost_raw, "gnutls_x509_privkey_export_gost_raw");
        lib.bindSymbol_stdcall(gnutls_x509_privkey_sign_data, "gnutls_x509_privkey_sign_data");
        lib.bindSymbol_stdcall(gnutls_x509_crq_sign, "gnutls_x509_crq_sign");
        lib.bindSymbol_stdcall(gnutls_x509_crq_sign2, "gnutls_x509_crq_sign2");
        lib.bindSymbol_stdcall(gnutls_x509_crq_print, "gnutls_x509_crq_print");
        lib.bindSymbol_stdcall(gnutls_x509_crq_verify, "gnutls_x509_crq_verify");
        lib.bindSymbol_stdcall(gnutls_x509_crq_init, "gnutls_x509_crq_init");
        lib.bindSymbol_stdcall(gnutls_x509_crq_deinit, "gnutls_x509_crq_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_crq_import, "gnutls_x509_crq_import");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_private_key_usage_period, "gnutls_x509_crq_get_private_key_usage_period");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_dn, "gnutls_x509_crq_get_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_dn2, "gnutls_x509_crq_get_dn2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_x509_crq_get_dn3, "gnutls_x509_crq_get_dn3");

        lib.bindSymbol_stdcall(gnutls_x509_crq_get_dn_oid, "gnutls_x509_crq_get_dn_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_dn_by_oid, "gnutls_x509_crq_get_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_dn, "gnutls_x509_crq_set_dn");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_dn_by_oid, "gnutls_x509_crq_set_dn_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_version, "gnutls_x509_crq_set_version");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_version, "gnutls_x509_crq_get_version");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_key, "gnutls_x509_crq_set_key");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            lib.bindSymbol_stdcall(gnutls_x509_crq_set_extension_by_oid, "gnutls_x509_crq_set_extension_by_oid");

        lib.bindSymbol_stdcall(gnutls_x509_crq_set_challenge_password, "gnutls_x509_crq_set_challenge_password");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_challenge_password, "gnutls_x509_crq_get_challenge_password");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_attribute_by_oid, "gnutls_x509_crq_set_attribute_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_attribute_by_oid, "gnutls_x509_crq_get_attribute_by_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_export, "gnutls_x509_crq_export");
        lib.bindSymbol_stdcall(gnutls_x509_crq_export2, "gnutls_x509_crq_export2");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_crq, "gnutls_x509_crt_set_crq");
        lib.bindSymbol_stdcall(gnutls_x509_crt_set_crq_extensions, "gnutls_x509_crt_set_crq_extensions");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            lib.bindSymbol_stdcall(gnutls_x509_crt_set_crq_extension_by_oid, "gnutls_x509_crt_set_crq_extension_by_oid");

        lib.bindSymbol_stdcall(gnutls_x509_crq_set_private_key_usage_period, "gnutls_x509_crq_set_private_key_usage_period");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_key_rsa_raw, "gnutls_x509_crq_set_key_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_subject_alt_name, "gnutls_x509_crq_set_subject_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_subject_alt_othername, "gnutls_x509_crq_set_subject_alt_othername");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_key_usage, "gnutls_x509_crq_set_key_usage");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_basic_constraints, "gnutls_x509_crq_set_basic_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_crq_set_key_purpose_oid, "gnutls_x509_crq_set_key_purpose_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_key_purpose_oid, "gnutls_x509_crq_get_key_purpose_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_extension_data, "gnutls_x509_crq_get_extension_data");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_extension_data2, "gnutls_x509_crq_get_extension_data2");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_extension_info, "gnutls_x509_crq_get_extension_info");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_attribute_data, "gnutls_x509_crq_get_attribute_data");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_attribute_info, "gnutls_x509_crq_get_attribute_info");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_pk_algorithm, "gnutls_x509_crq_get_pk_algorithm");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_x509_crq_get_spki, "gnutls_x509_crq_get_spki");
            lib.bindSymbol_stdcall(gnutls_x509_crq_set_spki, "gnutls_x509_crq_set_spki");
        }

        lib.bindSymbol_stdcall(gnutls_x509_crq_get_signature_oid, "gnutls_x509_crq_get_signature_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_pk_oid, "gnutls_x509_crq_get_pk_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_key_id, "gnutls_x509_crq_get_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_key_rsa_raw, "gnutls_x509_crq_get_key_rsa_raw");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_key_usage, "gnutls_x509_crq_get_key_usage");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_basic_constraints, "gnutls_x509_crq_get_basic_constraints");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_subject_alt_name, "gnutls_x509_crq_get_subject_alt_name");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_subject_alt_othername_oid, "gnutls_x509_crq_get_subject_alt_othername_oid");
        lib.bindSymbol_stdcall(gnutls_x509_crq_get_extension_by_oid, "gnutls_x509_crq_get_extension_by_oid");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        {
            lib.bindSymbol_stdcall(gnutls_x509_crq_get_tlsfeatures, "gnutls_x509_crq_get_tlsfeatures");
            lib.bindSymbol_stdcall(gnutls_x509_crq_set_tlsfeatures, "gnutls_x509_crq_set_tlsfeatures");
        }

        lib.bindSymbol_stdcall(gnutls_x509_crt_get_extension_by_oid2, "gnutls_x509_crt_get_extension_by_oid2");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_init, "gnutls_x509_trust_list_init");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_deinit, "gnutls_x509_trust_list_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_get_issuer, "gnutls_x509_trust_list_get_issuer");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_get_issuer_by_dn, "gnutls_x509_trust_list_get_issuer_by_dn");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_get_issuer_by_subject_key_id, "gnutls_x509_trust_list_get_issuer_by_subject_key_id");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_cas, "gnutls_x509_trust_list_add_cas");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_remove_cas, "gnutls_x509_trust_list_remove_cas");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_named_crt, "gnutls_x509_trust_list_add_named_crt");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_crls, "gnutls_x509_trust_list_add_crls");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_iter_get_ca, "gnutls_x509_trust_list_iter_get_ca");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_iter_deinit, "gnutls_x509_trust_list_iter_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_verify_named_crt, "gnutls_x509_trust_list_verify_named_crt");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_verify_crt2, "gnutls_x509_trust_list_verify_crt2");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_verify_crt, "gnutls_x509_trust_list_verify_crt");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_trust_mem, "gnutls_x509_trust_list_add_trust_mem");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_trust_file, "gnutls_x509_trust_list_add_trust_file");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_trust_dir, "gnutls_x509_trust_list_add_trust_dir");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_remove_trust_file, "gnutls_x509_trust_list_remove_trust_file");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_remove_trust_mem, "gnutls_x509_trust_list_remove_trust_mem");
        lib.bindSymbol_stdcall(gnutls_x509_trust_list_add_system_trust, "gnutls_x509_trust_list_add_system_trust");
        lib.bindSymbol_stdcall(gnutls_certificate_set_trust_list, "gnutls_certificate_set_trust_list");
        lib.bindSymbol_stdcall(gnutls_certificate_get_trust_list, "gnutls_certificate_get_trust_list");
        lib.bindSymbol_stdcall(gnutls_x509_ext_deinit, "gnutls_x509_ext_deinit");
        lib.bindSymbol_stdcall(gnutls_x509_ext_print, "gnutls_x509_ext_print");
    }
}
