module bindbc.gnutls.pkcs11;

import bindbc.gnutls.config;
import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import bindbc.gnutls.x509_ext;
import core.stdc.config;
import core.sys.posix.sys.types;

enum GNUTLS_PKCS11_MAX_PIN_LEN = 32;

struct gnutls_pkcs11_obj_st;
alias gnutls_pkcs11_obj_t = gnutls_pkcs11_obj_st*;

enum GNUTLS_PKCS11_FLAG_MANUAL = 0;
enum GNUTLS_PKCS11_FLAG_AUTO = 1;
enum GNUTLS_PKCS11_FLAG_AUTO_TRUSTED = 1 << 1;

enum gnutls_pkcs11_obj_flags
{
    GNUTLS_PKCS11_OBJ_FLAG_LOGIN = 1 << 0,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED = 1 << 1,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_SENSITIVE = 1 << 2,
    GNUTLS_PKCS11_OBJ_FLAG_LOGIN_SO = 1 << 3,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_PRIVATE = 1 << 4,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_PRIVATE = 1 << 5,
    GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_ANY = 1 << 6,
    GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_TRUSTED = GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_DISTRUSTED = 1 << 8,
    GNUTLS_PKCS11_OBJ_FLAG_RETRIEVE_DISTRUSTED = GNUTLS_PKCS11_OBJ_FLAG_MARK_DISTRUSTED,
    GNUTLS_PKCS11_OBJ_FLAG_COMPARE = 1 << 9,
    GNUTLS_PKCS11_OBJ_FLAG_PRESENT_IN_TRUSTED_MODULE = 1 << 10,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_CA = 1 << 11,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_KEY_WRAP = 1 << 12,
    GNUTLS_PKCS11_OBJ_FLAG_COMPARE_KEY = 1 << 13,
    GNUTLS_PKCS11_OBJ_FLAG_OVERWRITE_TRUSTMOD_EXT = 1 << 14,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_ALWAYS_AUTH = 1 << 15,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_EXTRACTABLE = 1 << 16,
    GNUTLS_PKCS11_OBJ_FLAG_NEVER_EXTRACTABLE = 1 << 17,
    GNUTLS_PKCS11_OBJ_FLAG_CRT = 1 << 18,
    GNUTLS_PKCS11_OBJ_FLAG_WITH_PRIVKEY = 1 << 19,
    GNUTLS_PKCS11_OBJ_FLAG_PUBKEY = 1 << 20,
    GNUTLS_PKCS11_OBJ_FLAG_NO_STORE_PUBKEY = GNUTLS_PKCS11_OBJ_FLAG_PUBKEY,
    GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY = 1 << 21,
    GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_SENSITIVE = 1 << 22 /// Available from GnuTLS 3.6.3
}

alias gnutls_pkcs11_obj_attr_t = gnutls_pkcs11_obj_flags;

enum gnutls_pkcs11_url_type_t
{
    GNUTLS_PKCS11_URL_GENERIC = 0,
    GNUTLS_PKCS11_URL_LIB = 1,
    GNUTLS_PKCS11_URL_LIB_VERSION = 2
}

enum gnutls_pkcs11_obj_info_t
{
    GNUTLS_PKCS11_OBJ_ID_HEX = 1,
    GNUTLS_PKCS11_OBJ_LABEL = 2,
    GNUTLS_PKCS11_OBJ_TOKEN_LABEL = 3,
    GNUTLS_PKCS11_OBJ_TOKEN_SERIAL = 4,
    GNUTLS_PKCS11_OBJ_TOKEN_MANUFACTURER = 5,
    GNUTLS_PKCS11_OBJ_TOKEN_MODEL = 6,
    GNUTLS_PKCS11_OBJ_ID = 7,

    GNUTLS_PKCS11_OBJ_LIBRARY_VERSION = 8,
    GNUTLS_PKCS11_OBJ_LIBRARY_DESCRIPTION = 9,
    GNUTLS_PKCS11_OBJ_LIBRARY_MANUFACTURER = 10
}

enum GNUTLS_PKCS11_OBJ_ATTR_CRT_ALL = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_CRT;
enum GNUTLS_PKCS11_OBJ_ATTR_MATCH = 0;
enum GNUTLS_PKCS11_OBJ_ATTR_ALL = 0;
enum GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_CRT | gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED;
enum GNUTLS_PKCS11_OBJ_ATTR_CRT_WITH_PRIVKEY = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_CRT | gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_WITH_PRIVKEY;
enum GNUTLS_PKCS11_OBJ_ATTR_CRT_TRUSTED_CA = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_CRT | gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_MARK_CA | gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_MARK_TRUSTED;
enum GNUTLS_PKCS11_OBJ_ATTR_PUBKEY = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_PUBKEY;
enum GNUTLS_PKCS11_OBJ_ATTR_PRIVKEY = gnutls_pkcs11_obj_flags.GNUTLS_PKCS11_OBJ_FLAG_PRIVKEY;

enum gnutls_pkcs11_token_info_t
{
    GNUTLS_PKCS11_TOKEN_LABEL = 0,
    GNUTLS_PKCS11_TOKEN_SERIAL = 1,
    GNUTLS_PKCS11_TOKEN_MANUFACTURER = 2,
    GNUTLS_PKCS11_TOKEN_MODEL = 3,
    GNUTLS_PKCS11_TOKEN_MODNAME = 4
}

enum gnutls_pkcs11_obj_type_t
{
    GNUTLS_PKCS11_OBJ_UNKNOWN = 0,
    GNUTLS_PKCS11_OBJ_X509_CRT = 1,
    GNUTLS_PKCS11_OBJ_PUBKEY = 2,
    GNUTLS_PKCS11_OBJ_PRIVKEY = 3,
    GNUTLS_PKCS11_OBJ_SECRET_KEY = 4,
    GNUTLS_PKCS11_OBJ_DATA = 5,
    GNUTLS_PKCS11_OBJ_X509_CRT_EXTENSION = 6
}

enum GNUTLS_PKCS11_TOKEN_HW = 1;
enum GNUTLS_PKCS11_TOKEN_TRUSTED = 1 << 1;
enum GNUTLS_PKCS11_TOKEN_RNG = 1 << 2;
enum GNUTLS_PKCS11_TOKEN_LOGIN_REQUIRED = 1 << 3;
enum GNUTLS_PKCS11_TOKEN_PROTECTED_AUTHENTICATION_PATH = 1 << 4;
enum GNUTLS_PKCS11_TOKEN_INITIALIZED = 1 << 5;
enum GNUTLS_PKCS11_TOKEN_USER_PIN_COUNT_LOW = 1 << 6;
enum GNUTLS_PKCS11_TOKEN_USER_PIN_FINAL_TRY = 1 << 7;
enum GNUTLS_PKCS11_TOKEN_USER_PIN_LOCKED = 1 << 8;
enum GNUTLS_PKCS11_TOKEN_SO_PIN_COUNT_LOW = 1 << 9;
enum GNUTLS_PKCS11_TOKEN_SO_PIN_FINAL_TRY = 1 << 10;
enum GNUTLS_PKCS11_TOKEN_SO_PIN_LOCKED = 1 << 11;
enum GNUTLS_PKCS11_TOKEN_USER_PIN_INITIALIZED = 1 << 12;
enum GNUTLS_PKCS11_TOKEN_ERROR_STATE = 1 << 13;

extern(C) nothrow @nogc
{
    alias gnutls_pkcs11_token_callback_t = int function (void* userdata, const char* label, uint retry);
}

extern (D) nothrow @nogc
{
    int gnutls_pkcs11_copy_x509_crt(const(char)* url, gnutls_x509_crt_t crt, const(char)* label, uint flags)
    {
        return gnutls_pkcs11_copy_x509_crt2(url, crt, label, null, flags);
    }

    int gnutls_pkcs11_copy_x509_privkey(const(char)* url, gnutls_x509_privkey_t key, const(char)* label, uint usage, uint flags)
    {
        return gnutls_pkcs11_copy_x509_privkey2(url, key, label, null, usage, flags);
    }

    int gnutls_pkcs11_privkey_generate(const(char)* url, gnutls_pk_algorithm_t pk, uint bits, const(char)* label, uint flags)
    {
        return gnutls_pkcs11_privkey_generate3(url, pk, bits, label, null, gnutls_x509_crt_fmt_t.GNUTLS_X509_FMT_DER, null, 0, flags);
    }

    int gnutls_pkcs11_privkey_generate2(const(char)* url, gnutls_pk_algorithm_t pk, uint bits, const(char)* label, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint flags)
    {
        return gnutls_pkcs11_privkey_generate3(url, pk, bits, label, null, fmt, pubkey, 0, flags);
    }
}

alias gnutls_x509_crt_import_pkcs11_url = gnutls_x509_crt_import_url;

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_pkcs11_init (uint flags, const(char)* deprecated_config_file);
    int gnutls_pkcs11_reinit ();
    void gnutls_pkcs11_deinit ();
    void gnutls_pkcs11_set_token_function (gnutls_pkcs11_token_callback_t fn, void* userdata);
    void gnutls_pkcs11_set_pin_function (gnutls_pin_callback_t fn, void* userdata);
    gnutls_pin_callback_t gnutls_pkcs11_get_pin_function (void** userdata);
    int gnutls_pkcs11_add_provider (const(char)* name, const(char)* params);
    int gnutls_pkcs11_obj_init (gnutls_pkcs11_obj_t* obj);
    void gnutls_pkcs11_obj_set_pin_function (gnutls_pkcs11_obj_t obj, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_pkcs11_obj_import_url (gnutls_pkcs11_obj_t obj, const(char)* url, uint flags);
    int gnutls_pkcs11_obj_export_url (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_url_type_t detailed, char** url);
    void gnutls_pkcs11_obj_deinit (gnutls_pkcs11_obj_t obj);
    int gnutls_pkcs11_obj_export (gnutls_pkcs11_obj_t obj, void* output_data, size_t* output_data_size);
    int gnutls_pkcs11_obj_export2 (gnutls_pkcs11_obj_t obj, gnutls_datum_t* out_);
    int gnutls_pkcs11_obj_export3 (gnutls_pkcs11_obj_t obj, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* out_);
    int gnutls_pkcs11_get_raw_issuer (const(char)* url, gnutls_x509_crt_t cert, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
    int gnutls_pkcs11_get_raw_issuer_by_dn (const(char)* url, const(gnutls_datum_t)* dn, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
    int gnutls_pkcs11_get_raw_issuer_by_subject_key_id (const(char)* url, const(gnutls_datum_t)* dn, const(gnutls_datum_t)* spki, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
    uint gnutls_pkcs11_crt_is_known (const(char)* url, gnutls_x509_crt_t cert, uint flags);
    int gnutls_pkcs11_copy_pubkey (const(char)* token_url, gnutls_pubkey_t crt, const(char)* label, const(gnutls_datum_t)* cid, uint key_usage, uint flags);
    int gnutls_pkcs11_copy_x509_crt2 (const(char)* token_url, gnutls_x509_crt_t crt, const(char)* label, const(gnutls_datum_t)* id, uint flags);
    int gnutls_pkcs11_copy_x509_privkey2 (const(char)* token_url, gnutls_x509_privkey_t key, const(char)* label, const(gnutls_datum_t)* cid, uint key_usage, uint flags);
    int gnutls_pkcs11_delete_url (const(char)* object_url, uint flags);
    int gnutls_pkcs11_copy_secret_key (const(char)* token_url, gnutls_datum_t* key, const(char)* label, uint key_usage, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_pkcs11_obj_get_ptr (gnutls_pkcs11_obj_t obj, void** ptr, void** session, void** ohandle, c_ulong* slot_id, uint flags);

    int gnutls_pkcs11_obj_get_info (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);
    int gnutls_pkcs11_obj_set_info (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, const(void)* data, size_t data_size, uint flags);
    int gnutls_pkcs11_token_init (const(char)* token_url, const(char)* so_pin, const(char)* label);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_pkcs11_token_get_ptr (const(char)* url, void** ptr, c_ulong* slot_id, uint flags);

    int gnutls_pkcs11_token_get_mechanism (const(char)* url, uint idx, c_ulong* mechanism);
    uint gnutls_pkcs11_token_check_mechanism (const(char)* url, c_ulong mechanism, void* ptr, uint psize, uint flags);
    int gnutls_pkcs11_token_set_pin (const(char)* token_url, const(char)* oldpin, const(char)* newpin, uint flags);
    int gnutls_pkcs11_token_get_url (uint seq, gnutls_pkcs11_url_type_t detailed, char** url);
    int gnutls_pkcs11_token_get_info (const(char)* url, gnutls_pkcs11_token_info_t ttype, void* output, size_t* output_size);
    int gnutls_pkcs11_token_get_flags (const(char)* url, uint* flags);
    int gnutls_pkcs11_obj_list_import_url3 (gnutls_pkcs11_obj_t* p_list, uint* n_list, const(char)* url, uint flags);
    int gnutls_pkcs11_obj_list_import_url4 (gnutls_pkcs11_obj_t** p_list, uint* n_list, const(char)* url, uint flags);
    int gnutls_x509_crt_import_pkcs11 (gnutls_x509_crt_t crt, gnutls_pkcs11_obj_t pkcs11_crt);
    gnutls_pkcs11_obj_type_t gnutls_pkcs11_obj_get_type (gnutls_pkcs11_obj_t obj);
    const(char)* gnutls_pkcs11_type_get_name (gnutls_pkcs11_obj_type_t type);
    int gnutls_pkcs11_obj_get_exts (gnutls_pkcs11_obj_t obj, gnutls_x509_ext_st** exts, uint* exts_size, uint flags);
    int gnutls_pkcs11_obj_get_flags (gnutls_pkcs11_obj_t obj, uint* oflags);
    char* gnutls_pkcs11_obj_flags_get_str (uint flags);
    int gnutls_x509_crt_list_import_pkcs11 (gnutls_x509_crt_t* certs, uint cert_max, gnutls_pkcs11_obj_t* objs, uint flags);
    int gnutls_pkcs11_privkey_init (gnutls_pkcs11_privkey_t* key);
    int gnutls_pkcs11_privkey_cpy (gnutls_pkcs11_privkey_t dst, gnutls_pkcs11_privkey_t src);
    void gnutls_pkcs11_privkey_set_pin_function (gnutls_pkcs11_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
    void gnutls_pkcs11_privkey_deinit (gnutls_pkcs11_privkey_t key);
    int gnutls_pkcs11_privkey_get_pk_algorithm (gnutls_pkcs11_privkey_t key, uint* bits);
    int gnutls_pkcs11_privkey_get_info (gnutls_pkcs11_privkey_t pkey, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);
    int gnutls_pkcs11_privkey_import_url (gnutls_pkcs11_privkey_t pkey, const(char)* url, uint flags);
    int gnutls_pkcs11_privkey_export_url (gnutls_pkcs11_privkey_t key, gnutls_pkcs11_url_type_t detailed, char** url);
    uint gnutls_pkcs11_privkey_status (gnutls_pkcs11_privkey_t key);
    int gnutls_pkcs11_privkey_generate3 (const(char)* url, gnutls_pk_algorithm_t pk, uint bits, const(char)* label, const(gnutls_datum_t)* cid, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint key_usage, uint flags);
    int gnutls_pkcs11_privkey_export_pubkey (gnutls_pkcs11_privkey_t pkey, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint flags);
    int gnutls_pkcs11_token_get_random (const(char)* token_url, void* data, size_t len);
    int gnutls_pkcs11_copy_attached_extension (const(char)* token_url, gnutls_x509_crt_t crt, gnutls_datum_t* data, const(char)* label, uint flags);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_pkcs11_init = int function (uint flags, const(char)* deprecated_config_file);
        alias pgnutls_pkcs11_reinit = int function ();
        alias pgnutls_pkcs11_deinit = void function ();
        alias pgnutls_pkcs11_set_token_function = void function (gnutls_pkcs11_token_callback_t fn, void* userdata);
        alias pgnutls_pkcs11_set_pin_function = void function (gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_pkcs11_get_pin_function = gnutls_pin_callback_t function (void** userdata);
        alias pgnutls_pkcs11_add_provider = int function (const(char)* name, const(char)* params);
        alias pgnutls_pkcs11_obj_init = int function (gnutls_pkcs11_obj_t* obj);
        alias pgnutls_pkcs11_obj_set_pin_function = void function (gnutls_pkcs11_obj_t obj, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_pkcs11_obj_import_url = int function (gnutls_pkcs11_obj_t obj, const(char)* url, uint flags);
        alias pgnutls_pkcs11_obj_export_url = int function (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_url_type_t detailed, char** url);
        alias pgnutls_pkcs11_obj_deinit = void function (gnutls_pkcs11_obj_t obj);
        alias pgnutls_pkcs11_obj_export = int function (gnutls_pkcs11_obj_t obj, void* output_data, size_t* output_data_size);
        alias pgnutls_pkcs11_obj_export2 = int function (gnutls_pkcs11_obj_t obj, gnutls_datum_t* out_);
        alias pgnutls_pkcs11_obj_export3 = int function (gnutls_pkcs11_obj_t obj, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* out_);
        alias pgnutls_pkcs11_get_raw_issuer = int function (const(char)* url, gnutls_x509_crt_t cert, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
        alias pgnutls_pkcs11_get_raw_issuer_by_dn = int function (const(char)* url, const(gnutls_datum_t)* dn, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
        alias pgnutls_pkcs11_get_raw_issuer_by_subject_key_id = int function (const(char)* url, const(gnutls_datum_t)* dn, const(gnutls_datum_t)* spki, gnutls_datum_t* issuer, gnutls_x509_crt_fmt_t fmt, uint flags);
        alias pgnutls_pkcs11_crt_is_known = uint function (const(char)* url, gnutls_x509_crt_t cert, uint flags);
        alias pgnutls_pkcs11_copy_pubkey = int function (const(char)* token_url, gnutls_pubkey_t crt, const(char)* label, const(gnutls_datum_t)* cid, uint key_usage, uint flags);
        alias pgnutls_pkcs11_copy_x509_crt2 = int function (const(char)* token_url, gnutls_x509_crt_t crt, const(char)* label, const(gnutls_datum_t)* id, uint flags);
        alias pgnutls_pkcs11_copy_x509_privkey2 = int function (const(char)* token_url, gnutls_x509_privkey_t key, const(char)* label, const(gnutls_datum_t)* cid, uint key_usage, uint flags);
        alias pgnutls_pkcs11_delete_url = int function (const(char)* object_url, uint flags);
        alias pgnutls_pkcs11_copy_secret_key = int function (const(char)* token_url, gnutls_datum_t* key, const(char)* label, uint key_usage, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_pkcs11_obj_get_ptr = int function (gnutls_pkcs11_obj_t obj, void** ptr, void** session, void** ohandle, c_ulong* slot_id, uint flags);

        alias pgnutls_pkcs11_obj_get_info = int function (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);
        alias pgnutls_pkcs11_obj_set_info = int function (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, const(void)* data, size_t data_size, uint flags);
        alias pgnutls_pkcs11_token_init = int function (const(char)* token_url, const(char)* so_pin, const(char)* label);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_pkcs11_token_get_ptr = int function (const(char)* url, void** ptr, c_ulong* slot_id, uint flags);

        alias pgnutls_pkcs11_token_get_mechanism = int function (const(char)* url, uint idx, c_ulong* mechanism);
        alias pgnutls_pkcs11_token_check_mechanism = uint function (const(char)* url, c_ulong mechanism, void* ptr, uint psize, uint flags);
        alias pgnutls_pkcs11_token_set_pin = int function (const(char)* token_url, const(char)* oldpin, const(char)* newpin, uint flags);
        alias pgnutls_pkcs11_token_get_url = int function (uint seq, gnutls_pkcs11_url_type_t detailed, char** url);
        alias pgnutls_pkcs11_token_get_info = int function (const(char)* url, gnutls_pkcs11_token_info_t ttype, void* output, size_t* output_size);
        alias pgnutls_pkcs11_token_get_flags = int function (const(char)* url, uint* flags);
        alias pgnutls_pkcs11_obj_list_import_url3 = int function (gnutls_pkcs11_obj_t* p_list, uint* n_list, const(char)* url, uint flags);
        alias pgnutls_pkcs11_obj_list_import_url4 = int function (gnutls_pkcs11_obj_t** p_list, uint* n_list, const(char)* url, uint flags);
        alias pgnutls_x509_crt_import_pkcs11 = int function (gnutls_x509_crt_t crt, gnutls_pkcs11_obj_t pkcs11_crt);
        alias pgnutls_pkcs11_obj_get_type = gnutls_pkcs11_obj_type_t function (gnutls_pkcs11_obj_t obj);
        alias pgnutls_pkcs11_type_get_name = const(char)* function (gnutls_pkcs11_obj_type_t type);
        alias pgnutls_pkcs11_obj_get_exts = int function (gnutls_pkcs11_obj_t obj, gnutls_x509_ext_st** exts, uint* exts_size, uint flags);
        alias pgnutls_pkcs11_obj_get_flags = int function (gnutls_pkcs11_obj_t obj, uint* oflags);
        alias pgnutls_pkcs11_obj_flags_get_str = char* function (uint flags);
        alias pgnutls_x509_crt_list_import_pkcs11 = int function (gnutls_x509_crt_t* certs, uint cert_max, gnutls_pkcs11_obj_t* objs, uint flags);
        alias pgnutls_pkcs11_privkey_init = int function (gnutls_pkcs11_privkey_t* key);
        alias pgnutls_pkcs11_privkey_cpy = int function (gnutls_pkcs11_privkey_t dst, gnutls_pkcs11_privkey_t src);
        alias pgnutls_pkcs11_privkey_set_pin_function = void function (gnutls_pkcs11_privkey_t key, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_pkcs11_privkey_deinit = void function (gnutls_pkcs11_privkey_t key);
        alias pgnutls_pkcs11_privkey_get_pk_algorithm = int function (gnutls_pkcs11_privkey_t key, uint* bits);
        alias pgnutls_pkcs11_privkey_get_info = int function (gnutls_pkcs11_privkey_t pkey, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);
        alias pgnutls_pkcs11_privkey_import_url = int function (gnutls_pkcs11_privkey_t pkey, const(char)* url, uint flags);
        alias pgnutls_pkcs11_privkey_export_url = int function (gnutls_pkcs11_privkey_t key, gnutls_pkcs11_url_type_t detailed, char** url);
        alias pgnutls_pkcs11_privkey_status = uint function (gnutls_pkcs11_privkey_t key);
        alias pgnutls_pkcs11_privkey_generate3 = int function (const(char)* url, gnutls_pk_algorithm_t pk, uint bits, const(char)* label, const(gnutls_datum_t)* cid, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint key_usage, uint flags);
        alias pgnutls_pkcs11_privkey_export_pubkey = int function (gnutls_pkcs11_privkey_t pkey, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint flags);
        alias pgnutls_pkcs11_token_get_random = int function (const(char)* token_url, void* data, size_t len);
        alias pgnutls_pkcs11_copy_attached_extension = int function (const(char)* token_url, gnutls_x509_crt_t crt, gnutls_datum_t* data, const(char)* label, uint flags);
    }

    __gshared
    {
        pgnutls_pkcs11_init gnutls_pkcs11_init;
        pgnutls_pkcs11_reinit gnutls_pkcs11_reinit;
        pgnutls_pkcs11_deinit gnutls_pkcs11_deinit;
        pgnutls_pkcs11_set_token_function gnutls_pkcs11_set_token_function;
        pgnutls_pkcs11_set_pin_function gnutls_pkcs11_set_pin_function;
        pgnutls_pkcs11_get_pin_function gnutls_pkcs11_get_pin_function;
        pgnutls_pkcs11_add_provider gnutls_pkcs11_add_provider;
        pgnutls_pkcs11_obj_init gnutls_pkcs11_obj_init;
        pgnutls_pkcs11_obj_set_pin_function gnutls_pkcs11_obj_set_pin_function;
        pgnutls_pkcs11_obj_import_url gnutls_pkcs11_obj_import_url;
        pgnutls_pkcs11_obj_export_url gnutls_pkcs11_obj_export_url;
        pgnutls_pkcs11_obj_deinit gnutls_pkcs11_obj_deinit;
        pgnutls_pkcs11_obj_export gnutls_pkcs11_obj_export;
        pgnutls_pkcs11_obj_export2 gnutls_pkcs11_obj_export2;
        pgnutls_pkcs11_obj_export3 gnutls_pkcs11_obj_export3;
        pgnutls_pkcs11_get_raw_issuer gnutls_pkcs11_get_raw_issuer;
        pgnutls_pkcs11_get_raw_issuer_by_dn gnutls_pkcs11_get_raw_issuer_by_dn;
        pgnutls_pkcs11_get_raw_issuer_by_subject_key_id gnutls_pkcs11_get_raw_issuer_by_subject_key_id;
        pgnutls_pkcs11_crt_is_known gnutls_pkcs11_crt_is_known;
        pgnutls_pkcs11_copy_pubkey gnutls_pkcs11_copy_pubkey;
        pgnutls_pkcs11_copy_x509_crt2 gnutls_pkcs11_copy_x509_crt2;
        pgnutls_pkcs11_copy_x509_privkey2 gnutls_pkcs11_copy_x509_privkey2;
        pgnutls_pkcs11_delete_url gnutls_pkcs11_delete_url;
        pgnutls_pkcs11_copy_secret_key gnutls_pkcs11_copy_secret_key;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_pkcs11_obj_get_ptr gnutls_pkcs11_obj_get_ptr;

        pgnutls_pkcs11_obj_get_info gnutls_pkcs11_obj_get_info;
        pgnutls_pkcs11_obj_set_info gnutls_pkcs11_obj_set_info;
        pgnutls_pkcs11_token_init gnutls_pkcs11_token_init;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_pkcs11_token_get_ptr gnutls_pkcs11_token_get_ptr;

        pgnutls_pkcs11_token_get_mechanism gnutls_pkcs11_token_get_mechanism;
        pgnutls_pkcs11_token_check_mechanism gnutls_pkcs11_token_check_mechanism;
        pgnutls_pkcs11_token_set_pin gnutls_pkcs11_token_set_pin;
        pgnutls_pkcs11_token_get_url gnutls_pkcs11_token_get_url;
        pgnutls_pkcs11_token_get_info gnutls_pkcs11_token_get_info;
        pgnutls_pkcs11_token_get_flags gnutls_pkcs11_token_get_flags;
        pgnutls_pkcs11_obj_list_import_url3 gnutls_pkcs11_obj_list_import_url3;
        pgnutls_pkcs11_obj_list_import_url4 gnutls_pkcs11_obj_list_import_url4;
        pgnutls_x509_crt_import_pkcs11 gnutls_x509_crt_import_pkcs11;
        pgnutls_pkcs11_obj_get_type gnutls_pkcs11_obj_get_type;
        pgnutls_pkcs11_type_get_name gnutls_pkcs11_type_get_name;
        pgnutls_pkcs11_obj_get_exts gnutls_pkcs11_obj_get_exts;
        pgnutls_pkcs11_obj_get_flags gnutls_pkcs11_obj_get_flags;
        pgnutls_pkcs11_obj_flags_get_str gnutls_pkcs11_obj_flags_get_str;
        pgnutls_x509_crt_list_import_pkcs11 gnutls_x509_crt_list_import_pkcs11;
        pgnutls_pkcs11_privkey_init gnutls_pkcs11_privkey_init;
        pgnutls_pkcs11_privkey_cpy gnutls_pkcs11_privkey_cpy;
        pgnutls_pkcs11_privkey_set_pin_function gnutls_pkcs11_privkey_set_pin_function;
        pgnutls_pkcs11_privkey_deinit gnutls_pkcs11_privkey_deinit;
        pgnutls_pkcs11_privkey_get_pk_algorithm gnutls_pkcs11_privkey_get_pk_algorithm;
        pgnutls_pkcs11_privkey_get_info gnutls_pkcs11_privkey_get_info;
        pgnutls_pkcs11_privkey_import_url gnutls_pkcs11_privkey_import_url;
        pgnutls_pkcs11_privkey_export_url gnutls_pkcs11_privkey_export_url;
        pgnutls_pkcs11_privkey_status gnutls_pkcs11_privkey_status;
        pgnutls_pkcs11_privkey_generate3 gnutls_pkcs11_privkey_generate3;
        pgnutls_pkcs11_privkey_export_pubkey gnutls_pkcs11_privkey_export_pubkey;
        pgnutls_pkcs11_token_get_random gnutls_pkcs11_token_get_random;
        pgnutls_pkcs11_copy_attached_extension gnutls_pkcs11_copy_attached_extension;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindPkcs11(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_pkcs11_init, "gnutls_pkcs11_init");
        lib.bindSymbol_stdcall(gnutls_pkcs11_reinit, "gnutls_pkcs11_reinit");
        lib.bindSymbol_stdcall(gnutls_pkcs11_deinit, "gnutls_pkcs11_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs11_set_token_function, "gnutls_pkcs11_set_token_function");
        lib.bindSymbol_stdcall(gnutls_pkcs11_set_pin_function, "gnutls_pkcs11_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_pkcs11_get_pin_function, "gnutls_pkcs11_get_pin_function");
        lib.bindSymbol_stdcall(gnutls_pkcs11_add_provider, "gnutls_pkcs11_add_provider");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_init, "gnutls_pkcs11_obj_init");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_set_pin_function, "gnutls_pkcs11_obj_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_import_url, "gnutls_pkcs11_obj_import_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_export_url, "gnutls_pkcs11_obj_export_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_deinit, "gnutls_pkcs11_obj_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_export, "gnutls_pkcs11_obj_export");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_export2, "gnutls_pkcs11_obj_export2");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_export3, "gnutls_pkcs11_obj_export3");
        lib.bindSymbol_stdcall(gnutls_pkcs11_get_raw_issuer, "gnutls_pkcs11_get_raw_issuer");
        lib.bindSymbol_stdcall(gnutls_pkcs11_get_raw_issuer_by_dn, "gnutls_pkcs11_get_raw_issuer_by_dn");
        lib.bindSymbol_stdcall(gnutls_pkcs11_get_raw_issuer_by_subject_key_id, "gnutls_pkcs11_get_raw_issuer_by_subject_key_id");
        lib.bindSymbol_stdcall(gnutls_pkcs11_crt_is_known, "gnutls_pkcs11_crt_is_known");
        lib.bindSymbol_stdcall(gnutls_pkcs11_copy_pubkey, "gnutls_pkcs11_copy_pubkey");
        lib.bindSymbol_stdcall(gnutls_pkcs11_copy_x509_crt2, "gnutls_pkcs11_copy_x509_crt2");
        lib.bindSymbol_stdcall(gnutls_pkcs11_copy_x509_privkey2, "gnutls_pkcs11_copy_x509_privkey2");
        lib.bindSymbol_stdcall(gnutls_pkcs11_delete_url, "gnutls_pkcs11_delete_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_copy_secret_key, "gnutls_pkcs11_copy_secret_key");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_pkcs11_obj_get_ptr, "gnutls_pkcs11_obj_get_ptr");

        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_get_info, "gnutls_pkcs11_obj_get_info");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_set_info, "gnutls_pkcs11_obj_set_info");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_init, "gnutls_pkcs11_token_init");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_ptr, "gnutls_pkcs11_token_get_ptr");

        lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_mechanism, "gnutls_pkcs11_token_get_mechanism");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_check_mechanism, "gnutls_pkcs11_token_check_mechanism");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_set_pin, "gnutls_pkcs11_token_set_pin");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_url, "gnutls_pkcs11_token_get_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_info, "gnutls_pkcs11_token_get_info");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_flags, "gnutls_pkcs11_token_get_flags");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_list_import_url3, "gnutls_pkcs11_obj_list_import_url3");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_list_import_url4, "gnutls_pkcs11_obj_list_import_url4");
        lib.bindSymbol_stdcall(gnutls_x509_crt_import_pkcs11, "gnutls_x509_crt_import_pkcs11");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_get_type, "gnutls_pkcs11_obj_get_type");
        lib.bindSymbol_stdcall(gnutls_pkcs11_type_get_name, "gnutls_pkcs11_type_get_name");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_get_exts, "gnutls_pkcs11_obj_get_exts");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_get_flags, "gnutls_pkcs11_obj_get_flags");
        lib.bindSymbol_stdcall(gnutls_pkcs11_obj_flags_get_str, "gnutls_pkcs11_obj_flags_get_str");
        lib.bindSymbol_stdcall(gnutls_x509_crt_list_import_pkcs11, "gnutls_x509_crt_list_import_pkcs11");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_init, "gnutls_pkcs11_privkey_init");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_cpy, "gnutls_pkcs11_privkey_cpy");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_set_pin_function, "gnutls_pkcs11_privkey_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_deinit, "gnutls_pkcs11_privkey_deinit");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_get_pk_algorithm, "gnutls_pkcs11_privkey_get_pk_algorithm");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_get_info, "gnutls_pkcs11_privkey_get_info");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_import_url, "gnutls_pkcs11_privkey_import_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_export_url, "gnutls_pkcs11_privkey_export_url");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_status, "gnutls_pkcs11_privkey_status");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_generate3, "gnutls_pkcs11_privkey_generate3");
        lib.bindSymbol_stdcall(gnutls_pkcs11_privkey_export_pubkey, "gnutls_pkcs11_privkey_export_pubkey");
        lib.bindSymbol_stdcall(gnutls_pkcs11_token_get_random, "gnutls_pkcs11_token_get_random");
        lib.bindSymbol_stdcall(gnutls_pkcs11_copy_attached_extension, "gnutls_pkcs11_copy_attached_extension");
    }
}
