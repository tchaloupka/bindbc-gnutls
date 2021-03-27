import core.stdc.stdio;
import core.stdc.string;
import bindbc.gnutls;
import tests._loader;

extern (C) int main()
{
    loadLib();
    const(char)* ver = gnutls_check_version(null);
    printf("GnuTLS version: %s\n", ver);
    const(char)* numver = gnutls_check_version_numeric!(3, 6, 1);
    assert(numver && strcmp(ver, numver) == 0);
    numver = gnutls_check_version_numeric!(999, 7, 10);
    assert(!numver);
    return 0;
}
