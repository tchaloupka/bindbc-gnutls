module bindbc.gnutls.system_keys;

import bindbc.gnutls.gnutls;
extern (C):

struct system_key_iter_st;
alias gnutls_system_key_iter_t = system_key_iter_st*;

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    void gnutls_system_key_iter_deinit (gnutls_system_key_iter_t iter);
    int gnutls_system_key_iter_get_info (gnutls_system_key_iter_t* iter, uint cert_type, char** cert_url, char** key_url, char** label, gnutls_datum_t* der, uint flags);
    int gnutls_system_key_delete (const(char)* cert_url, const(char)* key_url);
    int gnutls_system_key_add_x509 (gnutls_x509_crt_t crt, gnutls_x509_privkey_t privkey, const(char)* label, char** cert_url, char** key_url);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_system_key_iter_deinit = void function (gnutls_system_key_iter_t iter);
        alias pgnutls_system_key_iter_get_info = int function (gnutls_system_key_iter_t* iter, uint cert_type, char** cert_url, char** key_url, char** label, gnutls_datum_t* der, uint flags);
        alias pgnutls_system_key_delete = int function (const(char)* cert_url, const(char)* key_url);
        alias pgnutls_system_key_add_x509 = int function (gnutls_x509_crt_t crt, gnutls_x509_privkey_t privkey, const(char)* label, char** cert_url, char** key_url);
    }

    __gshared
    {
        pgnutls_system_key_iter_deinit gnutls_system_key_iter_deinit;
        pgnutls_system_key_iter_get_info gnutls_system_key_iter_get_info;
        pgnutls_system_key_delete gnutls_system_key_delete;
        pgnutls_system_key_add_x509 gnutls_system_key_add_x509;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindSystemKeys(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_system_key_iter_deinit, "gnutls_system_key_iter_deinit");
        lib.bindSymbol_stdcall(gnutls_system_key_iter_get_info, "gnutls_system_key_iter_get_info");
        lib.bindSymbol_stdcall(gnutls_system_key_delete, "gnutls_system_key_delete");
        lib.bindSymbol_stdcall(gnutls_system_key_add_x509, "gnutls_system_key_add_x509");
    }
}
