module bindbc.gnutls.tpm;

import bindbc.gnutls.gnutls;

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

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_tpm_privkey_generate (gnutls_pk_algorithm_t pk, uint bits, const(char)* srk_password, const(char)* key_password, gnutls_tpmkey_fmt_t format, gnutls_x509_crt_fmt_t pub_format, gnutls_datum_t* privkey, gnutls_datum_t* pubkey, uint flags);
    void gnutls_tpm_key_list_deinit (gnutls_tpm_key_list_t list);
    int gnutls_tpm_key_list_get_url (gnutls_tpm_key_list_t list, uint idx, char** url, uint flags);
    int gnutls_tpm_get_registered (gnutls_tpm_key_list_t* list);
    int gnutls_tpm_privkey_delete (const(char)* url, const(char)* srk_password);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_tpm_privkey_generate = int function (gnutls_pk_algorithm_t pk, uint bits, const(char)* srk_password, const(char)* key_password, gnutls_tpmkey_fmt_t format, gnutls_x509_crt_fmt_t pub_format, gnutls_datum_t* privkey, gnutls_datum_t* pubkey, uint flags);
        alias pgnutls_tpm_key_list_deinit = void function (gnutls_tpm_key_list_t list);
        alias pgnutls_tpm_key_list_get_url = int function (gnutls_tpm_key_list_t list, uint idx, char** url, uint flags);
        alias pgnutls_tpm_get_registered = int function (gnutls_tpm_key_list_t* list);
        alias pgnutls_tpm_privkey_delete = int function (const(char)* url, const(char)* srk_password);
    }

    __gshared
    {
        pgnutls_tpm_privkey_generate gnutls_tpm_privkey_generate;
        pgnutls_tpm_key_list_deinit gnutls_tpm_key_list_deinit;
        pgnutls_tpm_key_list_get_url gnutls_tpm_key_list_get_url;
        pgnutls_tpm_get_registered gnutls_tpm_get_registered;
        pgnutls_tpm_privkey_delete gnutls_tpm_privkey_delete;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindTpm(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_tpm_privkey_generate, "gnutls_tpm_privkey_generate");
        lib.bindSymbol_stdcall(gnutls_tpm_key_list_deinit, "gnutls_tpm_key_list_deinit");
        lib.bindSymbol_stdcall(gnutls_tpm_key_list_get_url, "gnutls_tpm_key_list_get_url");
        lib.bindSymbol_stdcall(gnutls_tpm_get_registered, "gnutls_tpm_get_registered");
        lib.bindSymbol_stdcall(gnutls_tpm_privkey_delete, "gnutls_tpm_privkey_delete");
    }
}
