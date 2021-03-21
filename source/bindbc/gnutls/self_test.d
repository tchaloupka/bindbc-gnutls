module bindbc.gnutls.self_test;

import bindbc.gnutls.gnutls;

extern (C):

enum GNUTLS_SELF_TEST_FLAG_ALL = 1;
enum GNUTLS_SELF_TEST_FLAG_NO_COMPAT = 1 << 1;

int gnutls_cipher_self_test (uint flags, gnutls_cipher_algorithm_t cipher);
int gnutls_mac_self_test (uint flags, gnutls_mac_algorithm_t mac);
int gnutls_digest_self_test (uint flags, gnutls_digest_algorithm_t digest);
int gnutls_pk_self_test (uint flags, gnutls_pk_algorithm_t pk);
