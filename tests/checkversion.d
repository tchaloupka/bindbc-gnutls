import core.stdc.stdio;
import bindbc.gnutls;
import tests._loader;

extern (C) int main()
{
    loadLib();
    printf("GnuTLS version: %s\n", gnutls_check_version(null));
    return 0;
}
