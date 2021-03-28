/// Test that some global symbols are bounded correctly
module tests.symbols;

import core.stdc.stdio;
import core.stdc.string;
import bindbc.gnutls;
import tests._loader;

extern (C) int main()
{
    loadLib();
    printf("gnutls_ffdhe_2048_key_bits: %d\n", gnutls_ffdhe_2048_key_bits);
    assert(gnutls_ffdhe_2048_key_bits == 256);
    void* mem = gnutls_malloc(1024);
    assert(mem);
    gnutls_free(mem);
    return 0;
}
