#!/usr/bin/env dub
/+ dub.sdl:
    name "checkversion"
    dependency "bindbc-gnutls" path="../"
    libs "gnutls"
+/

import core.stdc.stdio;
import bindbc.gnutls;

extern (C) int main()
{
    printf("GnuTLS version: %s\n", gnutls_check_version(null));
    return 0;
}
