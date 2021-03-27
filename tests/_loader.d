module tests._loader;

import bindbc.gnutls;
import core.stdc.stdio;

version (BindGnuTLS_Static)
{
    void loadLib() {}
}
else:

void loadLib()
{
    import loader = bindbc.loader.sharedlib;
    auto res = loadGnuTLS();
    if (res < GnuTLSSupport.gnutls_3_5_0)
    {
        fprintf(stderr, "Error loading GnuTLS: %d\n", res);
        foreach(info; loader.errors)
        {
            fprintf(stderr, "\t%s: %s\n", info.error, info.message);
        }
        assert(0);
    }
    // else printf("GnuTLS sucesfully loaded\n");

    res = loadGnuTLS_Dane();
    if (res < GnuTLSSupport.gnutls_3_5_0)
    {
        fprintf(stderr, "Error loading GnuTLS-Dane: %d\n", res);
        foreach(info; loader.errors)
        {
            fprintf(stderr, "\t%s: %s\n", info.error, info.message);
        }
        assert(0);
    }
    // else printf("GnuTLS-Dane sucesfully loaded\n");
}
