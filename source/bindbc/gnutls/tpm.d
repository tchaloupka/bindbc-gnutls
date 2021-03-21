module bindbc.gnutls.tpm;

import bindbc.gnutls.gnutls;

extern (C):

struct tpm_key_list_st;
alias gnutls_tpm_key_list_t = tpm_key_list_st*;

enum GNUTLS_TPM_KEY_SIGNING = 1 << 1;
enum GNUTLS_TPM_REGISTER_KEY = 1 << 2;
enum GNUTLS_TPM_KEY_USER = 1 << 3;

enum gnutls_tpmkey_fmt_t
{
    GNUTLS_TPMKEY_FMT_RAW = 0,
    GNUTLS_TPMKEY_FMT_DER = GNUTLS_TPMKEY_FMT_RAW,
    GNUTLS_TPMKEY_FMT_CTK_PEM = 1
}

int gnutls_tpm_privkey_generate (gnutls_pk_algorithm_t pk, uint bits, const(char)* srk_password, const(char)* key_password, gnutls_tpmkey_fmt_t format, gnutls_x509_crt_fmt_t pub_format, gnutls_datum_t* privkey, gnutls_datum_t* pubkey, uint flags);

void gnutls_tpm_key_list_deinit (gnutls_tpm_key_list_t list);
int gnutls_tpm_key_list_get_url (gnutls_tpm_key_list_t list, uint idx, char** url, uint flags);
int gnutls_tpm_get_registered (gnutls_tpm_key_list_t* list);
int gnutls_tpm_privkey_delete (const(char)* url, const(char)* srk_password);
