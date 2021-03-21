module bindbc.gnutls.pkcs11;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import bindbc.gnutls.x509_ext;
import core.stdc.config;
import core.sys.posix.sys.types;

extern (C):

enum GNUTLS_PKCS11_MAX_PIN_LEN = 32;

alias gnutls_pkcs11_token_callback_t = int function (void* userdata, const char* label, uint retry);

struct gnutls_pkcs11_obj_st;
alias gnutls_pkcs11_obj_t = gnutls_pkcs11_obj_st*;

enum GNUTLS_PKCS11_FLAG_MANUAL = 0;
enum GNUTLS_PKCS11_FLAG_AUTO = 1;
enum GNUTLS_PKCS11_FLAG_AUTO_TRUSTED = 1 << 1;

int gnutls_pkcs11_init (uint flags, const(char)* deprecated_config_file);
int gnutls_pkcs11_reinit ();
void gnutls_pkcs11_deinit ();
void gnutls_pkcs11_set_token_function (gnutls_pkcs11_token_callback_t fn, void* userdata);

void gnutls_pkcs11_set_pin_function (gnutls_pin_callback_t fn, void* userdata);

gnutls_pin_callback_t gnutls_pkcs11_get_pin_function (void** userdata);

int gnutls_pkcs11_add_provider (const(char)* name, const(char)* params);
int gnutls_pkcs11_obj_init (gnutls_pkcs11_obj_t* obj);
void gnutls_pkcs11_obj_set_pin_function (gnutls_pkcs11_obj_t obj, gnutls_pin_callback_t fn, void* userdata);

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
    GNUTLS_PKCS11_OBJ_FLAG_MARK_NOT_SENSITIVE = 1 << 22
}

alias gnutls_pkcs11_obj_attr_t = gnutls_pkcs11_obj_flags;

enum gnutls_pkcs11_url_type_t
{
    GNUTLS_PKCS11_URL_GENERIC = 0,
    GNUTLS_PKCS11_URL_LIB = 1,
    GNUTLS_PKCS11_URL_LIB_VERSION = 2
}

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

extern (D) auto gnutls_pkcs11_copy_x509_crt(T0, T1, T2, T3)(auto ref T0 url, auto ref T1 crt, auto ref T2 label, auto ref T3 flags)
{
    return gnutls_pkcs11_copy_x509_crt2(url, crt, label, NULL, flags);
}

int gnutls_pkcs11_copy_x509_crt2 (const(char)* token_url, gnutls_x509_crt_t crt, const(char)* label, const(gnutls_datum_t)* id, uint flags);

extern (D) auto gnutls_pkcs11_copy_x509_privkey(T0, T1, T2, T3, T4)(auto ref T0 url, auto ref T1 key, auto ref T2 label, auto ref T3 usage, auto ref T4 flags)
{
    return gnutls_pkcs11_copy_x509_privkey2(url, key, label, NULL, usage, flags);
}

int gnutls_pkcs11_copy_x509_privkey2 (const(char)* token_url, gnutls_x509_privkey_t key, const(char)* label, const(gnutls_datum_t)* cid, uint key_usage, uint flags);

int gnutls_pkcs11_delete_url (const(char)* object_url, uint flags);

int gnutls_pkcs11_copy_secret_key (const(char)* token_url, gnutls_datum_t* key, const(char)* label, uint key_usage, uint flags);

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

int gnutls_pkcs11_obj_get_ptr (gnutls_pkcs11_obj_t obj, void** ptr, void** session, void** ohandle, c_ulong* slot_id, uint flags);

int gnutls_pkcs11_obj_get_info (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, void* output, size_t* output_size);
int gnutls_pkcs11_obj_set_info (gnutls_pkcs11_obj_t obj, gnutls_pkcs11_obj_info_t itype, const(void)* data, size_t data_size, uint flags);

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

int gnutls_pkcs11_token_init (const(char)* token_url, const(char)* so_pin, const(char)* label);

int gnutls_pkcs11_token_get_ptr (const(char)* url, void** ptr, c_ulong* slot_id, uint flags);

int gnutls_pkcs11_token_get_mechanism (const(char)* url, uint idx, c_ulong* mechanism);

uint gnutls_pkcs11_token_check_mechanism (const(char)* url, c_ulong mechanism, void* ptr, uint psize, uint flags);

int gnutls_pkcs11_token_set_pin (const(char)* token_url, const(char)* oldpin, const(char)* newpin, uint flags);

int gnutls_pkcs11_token_get_url (uint seq, gnutls_pkcs11_url_type_t detailed, char** url);
int gnutls_pkcs11_token_get_info (const(char)* url, gnutls_pkcs11_token_info_t ttype, void* output, size_t* output_size);

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

extern (D) auto gnutls_pkcs11_privkey_generate(T0, T1, T2, T3, T4)(auto ref T0 url, auto ref T1 pk, auto ref T2 bits, auto ref T3 label, auto ref T4 flags)
{
    return gnutls_pkcs11_privkey_generate3(url, pk, bits, label, NULL, 0, NULL, 0, flags);
}

extern (D) auto gnutls_pkcs11_privkey_generate2(T0, T1, T2, T3, T4, T5, T6)(auto ref T0 url, auto ref T1 pk, auto ref T2 bits, auto ref T3 label, auto ref T4 fmt, auto ref T5 pubkey, auto ref T6 flags)
{
    return gnutls_pkcs11_privkey_generate3(url, pk, bits, label, NULL, fmt, pubkey, 0, flags);
}

int gnutls_pkcs11_privkey_generate3 (const(char)* url, gnutls_pk_algorithm_t pk, uint bits, const(char)* label, const(gnutls_datum_t)* cid, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint key_usage, uint flags);

int gnutls_pkcs11_privkey_export_pubkey (gnutls_pkcs11_privkey_t pkey, gnutls_x509_crt_fmt_t fmt, gnutls_datum_t* pubkey, uint flags);

int gnutls_pkcs11_token_get_random (const(char)* token_url, void* data, size_t len);

int gnutls_pkcs11_copy_attached_extension (const(char)* token_url, gnutls_x509_crt_t crt, gnutls_datum_t* data, const(char)* label, uint flags);

alias gnutls_x509_crt_import_pkcs11_url = gnutls_x509_crt_import_url;
