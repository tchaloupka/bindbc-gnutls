module bindbc.gnutls.urls;

import bindbc.gnutls.gnutls;

extern(C) nothrow @nogc
{
    alias gnutls_privkey_import_url_func = int function (gnutls_privkey_t pkey, const(char)* url, uint flags);
    alias gnutls_x509_crt_import_url_func = int function (gnutls_x509_crt_t pkey, const(char)* url, uint flags);
    alias gnutls_pubkey_import_url_func = int function (gnutls_pubkey_t pkey, const(char)* url, uint flags);
    alias gnutls_get_raw_issuer_func = int function (const(char)* url, gnutls_x509_crt_t crt, gnutls_datum_t* issuer_der, uint flags);
}

struct gnutls_custom_url_st
{
    const(char)* name;
    uint name_size;
    gnutls_privkey_import_url_func import_key;
    gnutls_x509_crt_import_url_func import_crt;
    gnutls_pubkey_import_url_func import_pubkey;
    gnutls_get_raw_issuer_func get_issuer;
    void* future1;
    void* future2;
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:
    int gnutls_register_custom_url (const(gnutls_custom_url_st)* st);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_register_custom_url = int function (const(gnutls_custom_url_st)* st);
    }

    __gshared
    {
        pgnutls_register_custom_url gnutls_register_custom_url;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindUrls(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_register_custom_url, "gnutls_register_custom_url");
    }
}
