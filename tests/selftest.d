module tests.selftest;

import core.stdc.stdio;
import core.stdc.string;
import bindbc.gnutls;
import tests._loader;

extern (C) int main()
{
    loadLib();
    assert(0 == gnutls_cipher_self_test(0, gnutls_cipher_algorithm.GNUTLS_CIPHER_AES_256_CCM));
    assert(0 == gnutls_mac_self_test(0, gnutls_mac_algorithm_t.GNUTLS_MAC_SHA256));
    assert(0 == gnutls_digest_self_test(0, gnutls_digest_algorithm_t.GNUTLS_DIG_SHA256));
    assert(0 == gnutls_pk_self_test(0, gnutls_pk_algorithm_t.GNUTLS_PK_ECDSA));
    return 0;
}
