module bindbc.gnutls.system_keys;

import bindbc.gnutls.gnutls;
extern (C):

struct system_key_iter_st;
alias gnutls_system_key_iter_t = system_key_iter_st*;

void gnutls_system_key_iter_deinit (gnutls_system_key_iter_t iter);
int gnutls_system_key_iter_get_info (gnutls_system_key_iter_t* iter, uint cert_type, char** cert_url, char** key_url, char** label, gnutls_datum_t* der, uint flags);

int gnutls_system_key_delete (const(char)* cert_url, const(char)* key_url);

int gnutls_system_key_add_x509 (gnutls_x509_crt_t crt, gnutls_x509_privkey_t privkey, const(char)* label, char** cert_url, char** key_url);
