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
    auto res = loadGnuTLS();
    if (res != LoadRes.loaded)
    {
        printf("Error loading GnuTLS: %d\n", res);
        assert(0);
    }
    else printf("GnuTLS sucesfully loaded\n");
}
