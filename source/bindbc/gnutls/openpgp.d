module bindbc.gnutls.openpgp;

import bindbc.gnutls.gnutls;
import core.stdc.limits;
import core.sys.posix.sys.select;

extern (C):

enum gnutls_openpgp_crt_fmt
{
    GNUTLS_OPENPGP_FMT_RAW = 0,
    GNUTLS_OPENPGP_FMT_BASE64 = 1
}

alias gnutls_openpgp_crt_fmt_t = gnutls_openpgp_crt_fmt;

enum GNUTLS_OPENPGP_KEYID_SIZE = 8;
enum GNUTLS_OPENPGP_V4_FINGERPRINT_SIZE = 20;
alias gnutls_openpgp_keyid_t = ubyte[GNUTLS_OPENPGP_KEYID_SIZE];

int gnutls_openpgp_crt_init (gnutls_openpgp_crt_t* key);

void gnutls_openpgp_crt_deinit (gnutls_openpgp_crt_t key);

int gnutls_openpgp_crt_import (gnutls_openpgp_crt_t key, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format);
int gnutls_openpgp_crt_export (gnutls_openpgp_crt_t key, gnutls_openpgp_crt_fmt_t format, void* output_data, size_t* output_data_size);
int gnutls_openpgp_crt_export2 (gnutls_openpgp_crt_t key, gnutls_openpgp_crt_fmt_t format, gnutls_datum_t* out_);

int gnutls_openpgp_crt_print (gnutls_openpgp_crt_t cert, gnutls_certificate_print_formats_t format, gnutls_datum_t* out_);

enum GNUTLS_OPENPGP_MASTER_KEYID_IDX = INT_MAX;

int gnutls_openpgp_crt_get_key_usage (gnutls_openpgp_crt_t key, uint* key_usage);
int gnutls_openpgp_crt_get_fingerprint (gnutls_openpgp_crt_t key, void* fpr, size_t* fprlen);
int gnutls_openpgp_crt_get_subkey_fingerprint (gnutls_openpgp_crt_t key, uint idx, void* fpr, size_t* fprlen);

int gnutls_openpgp_crt_get_name (gnutls_openpgp_crt_t key, int idx, char* buf, size_t* sizeof_buf);

gnutls_pk_algorithm_t gnutls_openpgp_crt_get_pk_algorithm (gnutls_openpgp_crt_t key, uint* bits);

int gnutls_openpgp_crt_get_version (gnutls_openpgp_crt_t key);

time_t gnutls_openpgp_crt_get_creation_time (gnutls_openpgp_crt_t key);
time_t gnutls_openpgp_crt_get_expiration_time (gnutls_openpgp_crt_t key);

int gnutls_openpgp_crt_get_key_id (gnutls_openpgp_crt_t key, gnutls_openpgp_keyid_t keyid);

int gnutls_openpgp_crt_check_hostname (gnutls_openpgp_crt_t key, const(char)* hostname);
int gnutls_openpgp_crt_check_hostname2 (gnutls_openpgp_crt_t key, const(char)* hostname, uint flags);
int gnutls_openpgp_crt_check_email (gnutls_openpgp_crt_t key, const(char)* email, uint flags);

int gnutls_openpgp_crt_get_revoked_status (gnutls_openpgp_crt_t key);

int gnutls_openpgp_crt_get_subkey_count (gnutls_openpgp_crt_t key);
int gnutls_openpgp_crt_get_subkey_idx (gnutls_openpgp_crt_t key, const gnutls_openpgp_keyid_t keyid);
int gnutls_openpgp_crt_get_subkey_revoked_status (gnutls_openpgp_crt_t key, uint idx);
gnutls_pk_algorithm_t gnutls_openpgp_crt_get_subkey_pk_algorithm (gnutls_openpgp_crt_t key, uint idx, uint* bits);
time_t gnutls_openpgp_crt_get_subkey_creation_time (gnutls_openpgp_crt_t key, uint idx);
time_t gnutls_openpgp_crt_get_subkey_expiration_time (gnutls_openpgp_crt_t key, uint idx);
int gnutls_openpgp_crt_get_subkey_id (gnutls_openpgp_crt_t key, uint idx, gnutls_openpgp_keyid_t keyid);
int gnutls_openpgp_crt_get_subkey_usage (gnutls_openpgp_crt_t key, uint idx, uint* key_usage);

int gnutls_openpgp_crt_get_subkey_pk_dsa_raw (gnutls_openpgp_crt_t crt, uint idx, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);
int gnutls_openpgp_crt_get_subkey_pk_rsa_raw (gnutls_openpgp_crt_t crt, uint idx, gnutls_datum_t* m, gnutls_datum_t* e);
int gnutls_openpgp_crt_get_pk_dsa_raw (gnutls_openpgp_crt_t crt, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y);
int gnutls_openpgp_crt_get_pk_rsa_raw (gnutls_openpgp_crt_t crt, gnutls_datum_t* m, gnutls_datum_t* e);

int gnutls_openpgp_crt_get_preferred_key_id (gnutls_openpgp_crt_t key, gnutls_openpgp_keyid_t keyid);
int gnutls_openpgp_crt_set_preferred_key_id (gnutls_openpgp_crt_t key, const gnutls_openpgp_keyid_t keyid);

int gnutls_openpgp_privkey_init (gnutls_openpgp_privkey_t* key);
void gnutls_openpgp_privkey_deinit (gnutls_openpgp_privkey_t key);
gnutls_pk_algorithm_t gnutls_openpgp_privkey_get_pk_algorithm (gnutls_openpgp_privkey_t key, uint* bits);

gnutls_sec_param_t gnutls_openpgp_privkey_sec_param (gnutls_openpgp_privkey_t key);
int gnutls_openpgp_privkey_import (gnutls_openpgp_privkey_t key, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format, const(char)* password, uint flags);

int gnutls_openpgp_privkey_get_fingerprint (gnutls_openpgp_privkey_t key, void* fpr, size_t* fprlen);
int gnutls_openpgp_privkey_get_subkey_fingerprint (gnutls_openpgp_privkey_t key, uint idx, void* fpr, size_t* fprlen);
int gnutls_openpgp_privkey_get_key_id (gnutls_openpgp_privkey_t key, gnutls_openpgp_keyid_t keyid);
int gnutls_openpgp_privkey_get_subkey_count (gnutls_openpgp_privkey_t key);
int gnutls_openpgp_privkey_get_subkey_idx (gnutls_openpgp_privkey_t key, const gnutls_openpgp_keyid_t keyid);

int gnutls_openpgp_privkey_get_subkey_revoked_status (gnutls_openpgp_privkey_t key, uint idx);

int gnutls_openpgp_privkey_get_revoked_status (gnutls_openpgp_privkey_t key);

gnutls_pk_algorithm_t gnutls_openpgp_privkey_get_subkey_pk_algorithm (gnutls_openpgp_privkey_t key, uint idx, uint* bits);

time_t gnutls_openpgp_privkey_get_subkey_expiration_time (gnutls_openpgp_privkey_t key, uint idx);

int gnutls_openpgp_privkey_get_subkey_id (gnutls_openpgp_privkey_t key, uint idx, gnutls_openpgp_keyid_t keyid);

time_t gnutls_openpgp_privkey_get_subkey_creation_time (gnutls_openpgp_privkey_t key, uint idx);

int gnutls_openpgp_privkey_export_subkey_dsa_raw (gnutls_openpgp_privkey_t pkey, uint idx, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
int gnutls_openpgp_privkey_export_subkey_rsa_raw (gnutls_openpgp_privkey_t pkey, uint idx, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u);

int gnutls_openpgp_privkey_export_dsa_raw (gnutls_openpgp_privkey_t pkey, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* g, gnutls_datum_t* y, gnutls_datum_t* x);
int gnutls_openpgp_privkey_export_rsa_raw (gnutls_openpgp_privkey_t pkey, gnutls_datum_t* m, gnutls_datum_t* e, gnutls_datum_t* d, gnutls_datum_t* p, gnutls_datum_t* q, gnutls_datum_t* u);

int gnutls_openpgp_privkey_export (gnutls_openpgp_privkey_t key, gnutls_openpgp_crt_fmt_t format, const(char)* password, uint flags, void* output_data, size_t* output_data_size);
int gnutls_openpgp_privkey_export2 (gnutls_openpgp_privkey_t key, gnutls_openpgp_crt_fmt_t format, const(char)* password, uint flags, gnutls_datum_t* out_);

int gnutls_openpgp_privkey_set_preferred_key_id (gnutls_openpgp_privkey_t key, const gnutls_openpgp_keyid_t keyid);
int gnutls_openpgp_privkey_get_preferred_key_id (gnutls_openpgp_privkey_t key, gnutls_openpgp_keyid_t keyid);

int gnutls_openpgp_crt_get_auth_subkey (gnutls_openpgp_crt_t crt, gnutls_openpgp_keyid_t keyid, uint flag);

int gnutls_openpgp_keyring_init (gnutls_openpgp_keyring_t* keyring);
void gnutls_openpgp_keyring_deinit (gnutls_openpgp_keyring_t keyring);

int gnutls_openpgp_keyring_import (gnutls_openpgp_keyring_t keyring, const(gnutls_datum_t)* data, gnutls_openpgp_crt_fmt_t format);

int gnutls_openpgp_keyring_check_id (gnutls_openpgp_keyring_t ring, const gnutls_openpgp_keyid_t keyid, uint flags);

int gnutls_openpgp_crt_verify_ring (gnutls_openpgp_crt_t key, gnutls_openpgp_keyring_t keyring, uint flags, uint* verify);

int gnutls_openpgp_crt_verify_self (gnutls_openpgp_crt_t key, uint flags, uint* verify);

int gnutls_openpgp_keyring_get_crt (gnutls_openpgp_keyring_t ring, uint idx, gnutls_openpgp_crt_t* cert);

int gnutls_openpgp_keyring_get_crt_count (gnutls_openpgp_keyring_t ring);

alias gnutls_openpgp_recv_key_func = int function (gnutls_session_t session, const(ubyte)* keyfpr, uint keyfpr_length, gnutls_datum_t* key);

void gnutls_openpgp_set_recv_key_function (gnutls_session_t session, gnutls_openpgp_recv_key_func func);

int gnutls_certificate_set_openpgp_key (gnutls_certificate_credentials_t res, gnutls_openpgp_crt_t crt, gnutls_openpgp_privkey_t pkey);

int gnutls_certificate_get_openpgp_key (gnutls_certificate_credentials_t res, uint index, gnutls_openpgp_privkey_t* key);
int gnutls_certificate_get_openpgp_crt (gnutls_certificate_credentials_t res, uint index, gnutls_openpgp_crt_t** crt_list, uint* crt_list_size);

int gnutls_certificate_set_openpgp_key_file (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, gnutls_openpgp_crt_fmt_t format);
int gnutls_certificate_set_openpgp_key_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, gnutls_openpgp_crt_fmt_t format);

int gnutls_certificate_set_openpgp_key_file2 (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, const(char)* subkey_id, gnutls_openpgp_crt_fmt_t format);
int gnutls_certificate_set_openpgp_key_mem2 (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, const(char)* subkey_id, gnutls_openpgp_crt_fmt_t format);

int gnutls_certificate_set_openpgp_keyring_mem (gnutls_certificate_credentials_t c, const(ubyte)* data, size_t dlen, gnutls_openpgp_crt_fmt_t format);

int gnutls_certificate_set_openpgp_keyring_file (gnutls_certificate_credentials_t c, const(char)* file, gnutls_openpgp_crt_fmt_t format);
