module bindbc.gnutls.self_test;

import bindbc.gnutls.gnutls;

enum GNUTLS_SELF_TEST_FLAG_ALL = 1;
enum GNUTLS_SELF_TEST_FLAG_NO_COMPAT = 1 << 1;

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_cipher_self_test (uint flags, gnutls_cipher_algorithm_t cipher);
    int gnutls_mac_self_test (uint flags, gnutls_mac_algorithm_t mac);
    int gnutls_digest_self_test (uint flags, gnutls_digest_algorithm_t digest);
    int gnutls_pk_self_test (uint flags, gnutls_pk_algorithm_t pk);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_cipher_self_test = int function (uint flags, gnutls_cipher_algorithm_t cipher);
        alias pgnutls_mac_self_test = int function (uint flags, gnutls_mac_algorithm_t mac);
        alias pgnutls_digest_self_test = int function (uint flags, gnutls_digest_algorithm_t digest);
        alias pgnutls_pk_self_test = int function (uint flags, gnutls_pk_algorithm_t pk);
    }

    __gshared
    {
        pgnutls_cipher_self_test gnutls_cipher_self_test;
        pgnutls_mac_self_test gnutls_mac_self_test;
        pgnutls_digest_self_test gnutls_digest_self_test;
        pgnutls_pk_self_test gnutls_pk_self_test;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindSelfTest(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_cipher_self_test, "gnutls_cipher_self_test");
        lib.bindSymbol_stdcall(gnutls_mac_self_test, "gnutls_mac_self_test");
        lib.bindSymbol_stdcall(gnutls_digest_self_test, "gnutls_digest_self_test");
        lib.bindSymbol_stdcall(gnutls_pk_self_test, "gnutls_pk_self_test");
    }
}
