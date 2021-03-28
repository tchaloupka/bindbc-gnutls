module bindbc.gnutls.gnutls;

import bindbc.gnutls.config;
import core.stdc.config;
import core.sys.posix.sys.select;
import core.sys.posix.sys.types;
import core.sys.posix.sys.uio;

enum gnutls_cipher_algorithm
{
    GNUTLS_CIPHER_UNKNOWN = 0,
    GNUTLS_CIPHER_NULL = 1,
    GNUTLS_CIPHER_ARCFOUR_128 = 2,
    GNUTLS_CIPHER_3DES_CBC = 3,
    GNUTLS_CIPHER_AES_128_CBC = 4,
    GNUTLS_CIPHER_AES_256_CBC = 5,
    GNUTLS_CIPHER_ARCFOUR_40 = 6,
    GNUTLS_CIPHER_CAMELLIA_128_CBC = 7,
    GNUTLS_CIPHER_CAMELLIA_256_CBC = 8,
    GNUTLS_CIPHER_AES_192_CBC = 9,
    GNUTLS_CIPHER_AES_128_GCM = 10,
    GNUTLS_CIPHER_AES_256_GCM = 11,
    GNUTLS_CIPHER_CAMELLIA_192_CBC = 12,
    GNUTLS_CIPHER_SALSA20_256 = 13,
    GNUTLS_CIPHER_ESTREAM_SALSA20_256 = 14,
    GNUTLS_CIPHER_CAMELLIA_128_GCM = 15,
    GNUTLS_CIPHER_CAMELLIA_256_GCM = 16,
    GNUTLS_CIPHER_RC2_40_CBC = 17,
    GNUTLS_CIPHER_DES_CBC = 18,
    GNUTLS_CIPHER_AES_128_CCM = 19,
    GNUTLS_CIPHER_AES_256_CCM = 20,
    GNUTLS_CIPHER_AES_128_CCM_8 = 21,
    GNUTLS_CIPHER_AES_256_CCM_8 = 22,
    GNUTLS_CIPHER_CHACHA20_POLY1305 = 23,
    GNUTLS_CIPHER_GOST28147_TC26Z_CFB = 24,
    GNUTLS_CIPHER_GOST28147_CPA_CFB = 25,
    GNUTLS_CIPHER_GOST28147_CPB_CFB = 26,
    GNUTLS_CIPHER_GOST28147_CPC_CFB = 27,
    GNUTLS_CIPHER_GOST28147_CPD_CFB = 28,
    GNUTLS_CIPHER_AES_128_CFB8 = 29, /// Available from GnuTLS 3.6.5
    GNUTLS_CIPHER_AES_192_CFB8 = 30, /// Available from GnuTLS 3.6.5
    GNUTLS_CIPHER_AES_256_CFB8 = 31, /// Available from GnuTLS 3.6.5
    GNUTLS_CIPHER_AES_128_XTS = 32,
    GNUTLS_CIPHER_AES_256_XTS = 33,
    GNUTLS_CIPHER_GOST28147_TC26Z_CNT = 34, /// Available from GnuTLS 3.6.10
    GNUTLS_CIPHER_CHACHA20_64 = 35,
    GNUTLS_CIPHER_CHACHA20_32 = 36,
    GNUTLS_CIPHER_AES_128_SIV = 37, /// Available from GnuTLS 3.6.13
    GNUTLS_CIPHER_AES_256_SIV = 38, /// Available from GnuTLS 3.6.13
    GNUTLS_CIPHER_AES_192_GCM = 39, /// Available from GnuTLS 3.6.13

    GNUTLS_CIPHER_IDEA_PGP_CFB = 200,
    GNUTLS_CIPHER_3DES_PGP_CFB = 201,
    GNUTLS_CIPHER_CAST5_PGP_CFB = 202,
    GNUTLS_CIPHER_BLOWFISH_PGP_CFB = 203,
    GNUTLS_CIPHER_SAFER_SK128_PGP_CFB = 204,
    GNUTLS_CIPHER_AES128_PGP_CFB = 205,
    GNUTLS_CIPHER_AES192_PGP_CFB = 206,
    GNUTLS_CIPHER_AES256_PGP_CFB = 207,
    GNUTLS_CIPHER_TWOFISH_PGP_CFB = 208
}

alias gnutls_cipher_algorithm_t = gnutls_cipher_algorithm;

enum gnutls_kx_algorithm_t
{
    GNUTLS_KX_UNKNOWN = 0,
    GNUTLS_KX_RSA = 1,
    GNUTLS_KX_DHE_DSS = 2,
    GNUTLS_KX_DHE_RSA = 3,
    GNUTLS_KX_ANON_DH = 4,
    GNUTLS_KX_SRP = 5,
    GNUTLS_KX_RSA_EXPORT = 6,
    GNUTLS_KX_SRP_RSA = 7,
    GNUTLS_KX_SRP_DSS = 8,
    GNUTLS_KX_PSK = 9,
    GNUTLS_KX_DHE_PSK = 10,
    GNUTLS_KX_ANON_ECDH = 11,
    GNUTLS_KX_ECDHE_RSA = 12,
    GNUTLS_KX_ECDHE_ECDSA = 13,
    GNUTLS_KX_ECDHE_PSK = 14,
    GNUTLS_KX_RSA_PSK = 15,
    GNUTLS_KX_VKO_GOST_12 = 16
}

enum gnutls_params_type_t
{
    GNUTLS_PARAMS_RSA_EXPORT = 1,
    GNUTLS_PARAMS_DH = 2,
    GNUTLS_PARAMS_ECDH = 3
}

enum gnutls_credentials_type_t
{
    GNUTLS_CRD_CERTIFICATE = 1,
    GNUTLS_CRD_ANON = 2,
    GNUTLS_CRD_SRP = 3,
    GNUTLS_CRD_PSK = 4,
    GNUTLS_CRD_IA = 5
}

enum gnutls_mac_algorithm_t
{
    GNUTLS_MAC_UNKNOWN = 0,
    GNUTLS_MAC_NULL = 1,
    GNUTLS_MAC_MD5 = 2,
    GNUTLS_MAC_SHA1 = 3,
    GNUTLS_MAC_RMD160 = 4,
    GNUTLS_MAC_MD2 = 5,
    GNUTLS_MAC_SHA256 = 6,
    GNUTLS_MAC_SHA384 = 7,
    GNUTLS_MAC_SHA512 = 8,
    GNUTLS_MAC_SHA224 = 9,
    GNUTLS_MAC_SHA3_224 = 10,
    GNUTLS_MAC_SHA3_256 = 11,
    GNUTLS_MAC_SHA3_384 = 12,
    GNUTLS_MAC_SHA3_512 = 13,
    GNUTLS_MAC_MD5_SHA1 = 14,
    GNUTLS_MAC_GOSTR_94 = 15,
    GNUTLS_MAC_STREEBOG_256 = 16,
    GNUTLS_MAC_STREEBOG_512 = 17,

    GNUTLS_MAC_AEAD = 200,
    GNUTLS_MAC_UMAC_96 = 201,
    GNUTLS_MAC_UMAC_128 = 202,
    GNUTLS_MAC_AES_CMAC_128 = 203, /// Available from GnuTLS 3.6.5
    GNUTLS_MAC_AES_CMAC_256 = 204, /// Available from GnuTLS 3.6.5
    GNUTLS_MAC_AES_GMAC_128 = 205, /// Available from GnuTLS 3.6.9
    GNUTLS_MAC_AES_GMAC_192 = 206, /// Available from GnuTLS 3.6.9
    GNUTLS_MAC_AES_GMAC_256 = 207, /// Available from GnuTLS 3.6.9
    GNUTLS_MAC_GOST28147_TC26Z_IMIT = 208, /// Available from GnuTLS 3.6.10
    GNUTLS_MAC_SHAKE_128 = 209,
    GNUTLS_MAC_SHAKE_256 = 210
}

enum gnutls_digest_algorithm_t
{
    GNUTLS_DIG_UNKNOWN = gnutls_mac_algorithm_t.GNUTLS_MAC_UNKNOWN,
    GNUTLS_DIG_NULL = gnutls_mac_algorithm_t.GNUTLS_MAC_NULL,
    GNUTLS_DIG_MD5 = gnutls_mac_algorithm_t.GNUTLS_MAC_MD5,
    GNUTLS_DIG_SHA1 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA1,
    GNUTLS_DIG_RMD160 = gnutls_mac_algorithm_t.GNUTLS_MAC_RMD160,
    GNUTLS_DIG_MD2 = gnutls_mac_algorithm_t.GNUTLS_MAC_MD2,
    GNUTLS_DIG_SHA256 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA256,
    GNUTLS_DIG_SHA384 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA384,
    GNUTLS_DIG_SHA512 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA512,
    GNUTLS_DIG_SHA224 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA224,
    GNUTLS_DIG_SHA3_224 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA3_224,
    GNUTLS_DIG_SHA3_256 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA3_256,
    GNUTLS_DIG_SHA3_384 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA3_384,
    GNUTLS_DIG_SHA3_512 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA3_512,
    GNUTLS_DIG_MD5_SHA1 = gnutls_mac_algorithm_t.GNUTLS_MAC_MD5_SHA1,
    GNUTLS_DIG_GOSTR_94 = gnutls_mac_algorithm_t.GNUTLS_MAC_GOSTR_94,
    GNUTLS_DIG_STREEBOG_256 = gnutls_mac_algorithm_t.GNUTLS_MAC_STREEBOG_256,
    GNUTLS_DIG_STREEBOG_512 = gnutls_mac_algorithm_t.GNUTLS_MAC_STREEBOG_512,
    GNUTLS_DIG_SHAKE_128 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHAKE_128,
    GNUTLS_DIG_SHAKE_256 = gnutls_mac_algorithm_t.GNUTLS_MAC_SHAKE_256
}

enum gnutls_compression_method_t
{
    GNUTLS_COMP_UNKNOWN = 0,
    GNUTLS_COMP_NULL = 1,
    GNUTLS_COMP_DEFLATE = 2,
    GNUTLS_COMP_ZLIB = GNUTLS_COMP_DEFLATE
}

enum gnutls_init_flags_t
{
    GNUTLS_SERVER = 1,
    GNUTLS_CLIENT = 1 << 1,
    GNUTLS_DATAGRAM = 1 << 2,
    GNUTLS_NONBLOCK = 1 << 3,
    GNUTLS_NO_EXTENSIONS = 1 << 4,
    GNUTLS_NO_REPLAY_PROTECTION = 1 << 5,
    GNUTLS_NO_SIGNAL = 1 << 6,
    GNUTLS_ALLOW_ID_CHANGE = 1 << 7,
    GNUTLS_ENABLE_FALSE_START = 1 << 8,
    GNUTLS_FORCE_CLIENT_CERT = 1 << 9,
    GNUTLS_NO_TICKETS = 1 << 10, /// Available from GnuTLS 3.5.6
    GNUTLS_KEY_SHARE_TOP = 1 << 11,
    GNUTLS_KEY_SHARE_TOP2 = 1 << 12,
    GNUTLS_KEY_SHARE_TOP3 = 1 << 13,
    GNUTLS_POST_HANDSHAKE_AUTH = 1 << 14,
    GNUTLS_NO_AUTO_REKEY = 1 << 15,
    GNUTLS_SAFE_PADDING_CHECK = 1 << 16,
    GNUTLS_ENABLE_EARLY_START = 1 << 17, /// Available from GnuTLS 3.6.4
    GNUTLS_ENABLE_RAWPK = 1 << 18, /// Available from GnuTLS 3.6.6
    GNUTLS_AUTO_REAUTH = 1 << 19, /// Available from GnuTLS 3.6.5
    GNUTLS_ENABLE_EARLY_DATA = 1 << 20,
    GNUTLS_NO_AUTO_SEND_TICKET = 1 << 21 /// Available from GnuTLS 3.6.13
}

enum gnutls_alert_level_t
{
    GNUTLS_AL_WARNING = 1,
    GNUTLS_AL_FATAL = 2
}

enum gnutls_alert_description_t
{
    GNUTLS_A_CLOSE_NOTIFY = 0,
    GNUTLS_A_UNEXPECTED_MESSAGE = 10,
    GNUTLS_A_BAD_RECORD_MAC = 20,
    GNUTLS_A_DECRYPTION_FAILED = 21,
    GNUTLS_A_RECORD_OVERFLOW = 22,
    GNUTLS_A_DECOMPRESSION_FAILURE = 30,
    GNUTLS_A_HANDSHAKE_FAILURE = 40,
    GNUTLS_A_SSL3_NO_CERTIFICATE = 41,
    GNUTLS_A_BAD_CERTIFICATE = 42,
    GNUTLS_A_UNSUPPORTED_CERTIFICATE = 43,
    GNUTLS_A_CERTIFICATE_REVOKED = 44,
    GNUTLS_A_CERTIFICATE_EXPIRED = 45,
    GNUTLS_A_CERTIFICATE_UNKNOWN = 46,
    GNUTLS_A_ILLEGAL_PARAMETER = 47,
    GNUTLS_A_UNKNOWN_CA = 48,
    GNUTLS_A_ACCESS_DENIED = 49,
    GNUTLS_A_DECODE_ERROR = 50,
    GNUTLS_A_DECRYPT_ERROR = 51,
    GNUTLS_A_EXPORT_RESTRICTION = 60,
    GNUTLS_A_PROTOCOL_VERSION = 70,
    GNUTLS_A_INSUFFICIENT_SECURITY = 71,
    GNUTLS_A_INTERNAL_ERROR = 80,
    GNUTLS_A_INAPPROPRIATE_FALLBACK = 86,
    GNUTLS_A_USER_CANCELED = 90,
    GNUTLS_A_NO_RENEGOTIATION = 100,
    GNUTLS_A_MISSING_EXTENSION = 109,
    GNUTLS_A_UNSUPPORTED_EXTENSION = 110,
    GNUTLS_A_CERTIFICATE_UNOBTAINABLE = 111,
    GNUTLS_A_UNRECOGNIZED_NAME = 112,
    GNUTLS_A_UNKNOWN_PSK_IDENTITY = 115,
    GNUTLS_A_CERTIFICATE_REQUIRED = 116,
    GNUTLS_A_NO_APPLICATION_PROTOCOL = 120,
    GNUTLS_A_MAX = GNUTLS_A_NO_APPLICATION_PROTOCOL
}

enum gnutls_handshake_description_t
{
    GNUTLS_HANDSHAKE_HELLO_REQUEST = 0,
    GNUTLS_HANDSHAKE_CLIENT_HELLO = 1,
    GNUTLS_HANDSHAKE_SERVER_HELLO = 2,
    GNUTLS_HANDSHAKE_HELLO_VERIFY_REQUEST = 3,
    GNUTLS_HANDSHAKE_NEW_SESSION_TICKET = 4,
    GNUTLS_HANDSHAKE_END_OF_EARLY_DATA = 5,
    GNUTLS_HANDSHAKE_ENCRYPTED_EXTENSIONS = 8,
    GNUTLS_HANDSHAKE_CERTIFICATE_PKT = 11,
    GNUTLS_HANDSHAKE_SERVER_KEY_EXCHANGE = 12,
    GNUTLS_HANDSHAKE_CERTIFICATE_REQUEST = 13,
    GNUTLS_HANDSHAKE_SERVER_HELLO_DONE = 14,
    GNUTLS_HANDSHAKE_CERTIFICATE_VERIFY = 15,
    GNUTLS_HANDSHAKE_CLIENT_KEY_EXCHANGE = 16,
    GNUTLS_HANDSHAKE_FINISHED = 20,
    GNUTLS_HANDSHAKE_CERTIFICATE_STATUS = 22,
    GNUTLS_HANDSHAKE_SUPPLEMENTAL = 23,
    GNUTLS_HANDSHAKE_KEY_UPDATE = 24,
    GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC = 254,
    GNUTLS_HANDSHAKE_CLIENT_HELLO_V2 = 1024,
    GNUTLS_HANDSHAKE_HELLO_RETRY_REQUEST = 1025
}

const(char)* gnutls_handshake_description_get_name (gnutls_handshake_description_t type);

enum gnutls_certificate_status_t
{
    GNUTLS_CERT_INVALID = 1 << 1,
    GNUTLS_CERT_REVOKED = 1 << 5,
    GNUTLS_CERT_SIGNER_NOT_FOUND = 1 << 6,
    GNUTLS_CERT_SIGNER_NOT_CA = 1 << 7,
    GNUTLS_CERT_INSECURE_ALGORITHM = 1 << 8,
    GNUTLS_CERT_NOT_ACTIVATED = 1 << 9,
    GNUTLS_CERT_EXPIRED = 1 << 10,
    GNUTLS_CERT_SIGNATURE_FAILURE = 1 << 11,
    GNUTLS_CERT_REVOCATION_DATA_SUPERSEDED = 1 << 12,
    GNUTLS_CERT_UNEXPECTED_OWNER = 1 << 14,
    GNUTLS_CERT_REVOCATION_DATA_ISSUED_IN_FUTURE = 1 << 15,
    GNUTLS_CERT_SIGNER_CONSTRAINTS_FAILURE = 1 << 16,
    GNUTLS_CERT_MISMATCH = 1 << 17,
    GNUTLS_CERT_PURPOSE_MISMATCH = 1 << 18,
    GNUTLS_CERT_MISSING_OCSP_STATUS = 1 << 19,
    GNUTLS_CERT_INVALID_OCSP_STATUS = 1 << 20, /// Available from GnuTLS 3.5.1
    GNUTLS_CERT_UNKNOWN_CRIT_EXTENSIONS = 1 << 21 /// Available from GnuTLS 3.6.0
}

enum gnutls_certificate_request_t
{
    GNUTLS_CERT_IGNORE = 0,
    GNUTLS_CERT_REQUEST = 1,
    GNUTLS_CERT_REQUIRE = 2
}

enum gnutls_openpgp_crt_status_t
{
    GNUTLS_OPENPGP_CERT = 0,
    GNUTLS_OPENPGP_CERT_FINGERPRINT = 1
}

enum gnutls_close_request_t
{
    GNUTLS_SHUT_RDWR = 0,
    GNUTLS_SHUT_WR = 1
}

enum gnutls_protocol_t
{
    GNUTLS_SSL3 = 1,
    GNUTLS_TLS1_0 = 2,
    GNUTLS_TLS1 = GNUTLS_TLS1_0,
    GNUTLS_TLS1_1 = 3,
    GNUTLS_TLS1_2 = 4,
    GNUTLS_TLS1_3 = 5,

    GNUTLS_DTLS0_9 = 200,
    GNUTLS_DTLS1_0 = 201,
    GNUTLS_DTLS1_2 = 202,
    GNUTLS_DTLS_VERSION_MIN = GNUTLS_DTLS0_9,
    GNUTLS_DTLS_VERSION_MAX = GNUTLS_DTLS1_2,
    GNUTLS_TLS_VERSION_MAX = GNUTLS_TLS1_3,
    GNUTLS_VERSION_UNKNOWN = 0xff
}

enum gnutls_certificate_type_t
{
    GNUTLS_CRT_UNKNOWN = 0,
    GNUTLS_CRT_X509 = 1,
    GNUTLS_CRT_OPENPGP = 2,
    GNUTLS_CRT_RAWPK = 3,
    GNUTLS_CRT_MAX = GNUTLS_CRT_RAWPK
}

enum gnutls_x509_crt_fmt_t
{
    GNUTLS_X509_FMT_DER = 0,
    GNUTLS_X509_FMT_PEM = 1
}

enum gnutls_certificate_print_formats
{
    GNUTLS_CRT_PRINT_FULL = 0,
    GNUTLS_CRT_PRINT_ONELINE = 1,
    GNUTLS_CRT_PRINT_UNSIGNED_FULL = 2,
    GNUTLS_CRT_PRINT_COMPACT = 3,
    GNUTLS_CRT_PRINT_FULL_NUMBERS = 4
}

alias gnutls_certificate_print_formats_t = gnutls_certificate_print_formats;

enum gnutls_pk_algorithm_t
{
    GNUTLS_PK_UNKNOWN = 0,
    GNUTLS_PK_RSA = 1,
    GNUTLS_PK_DSA = 2,
    GNUTLS_PK_DH = 3,
    GNUTLS_PK_ECDSA = 4,
    GNUTLS_PK_ECDH_X25519 = 5,
    GNUTLS_PK_RSA_PSS = 6,
    GNUTLS_PK_EDDSA_ED25519 = 7,
    GNUTLS_PK_GOST_01 = 8,
    GNUTLS_PK_GOST_12_256 = 9,
    GNUTLS_PK_GOST_12_512 = 10,
    GNUTLS_PK_ECDH_X448 = 11,
    GNUTLS_PK_EDDSA_ED448 = 12,
    GNUTLS_PK_MAX = GNUTLS_PK_EDDSA_ED448
}


enum gnutls_sign_algorithm_t
{
    GNUTLS_SIGN_UNKNOWN = 0,
    GNUTLS_SIGN_RSA_SHA1 = 1,
    GNUTLS_SIGN_RSA_SHA = GNUTLS_SIGN_RSA_SHA1,
    GNUTLS_SIGN_DSA_SHA1 = 2,
    GNUTLS_SIGN_DSA_SHA = GNUTLS_SIGN_DSA_SHA1,
    GNUTLS_SIGN_RSA_MD5 = 3,
    GNUTLS_SIGN_RSA_MD2 = 4,
    GNUTLS_SIGN_RSA_RMD160 = 5,
    GNUTLS_SIGN_RSA_SHA256 = 6,
    GNUTLS_SIGN_RSA_SHA384 = 7,
    GNUTLS_SIGN_RSA_SHA512 = 8,
    GNUTLS_SIGN_RSA_SHA224 = 9,
    GNUTLS_SIGN_DSA_SHA224 = 10,
    GNUTLS_SIGN_DSA_SHA256 = 11,
    GNUTLS_SIGN_ECDSA_SHA1 = 12,
    GNUTLS_SIGN_ECDSA_SHA224 = 13,
    GNUTLS_SIGN_ECDSA_SHA256 = 14,
    GNUTLS_SIGN_ECDSA_SHA384 = 15,
    GNUTLS_SIGN_ECDSA_SHA512 = 16,
    GNUTLS_SIGN_DSA_SHA384 = 17,
    GNUTLS_SIGN_DSA_SHA512 = 18,
    GNUTLS_SIGN_ECDSA_SHA3_224 = 20,
    GNUTLS_SIGN_ECDSA_SHA3_256 = 21,
    GNUTLS_SIGN_ECDSA_SHA3_384 = 22,
    GNUTLS_SIGN_ECDSA_SHA3_512 = 23,

    GNUTLS_SIGN_DSA_SHA3_224 = 24,
    GNUTLS_SIGN_DSA_SHA3_256 = 25,
    GNUTLS_SIGN_DSA_SHA3_384 = 26,
    GNUTLS_SIGN_DSA_SHA3_512 = 27,
    GNUTLS_SIGN_RSA_SHA3_224 = 28,
    GNUTLS_SIGN_RSA_SHA3_256 = 29,
    GNUTLS_SIGN_RSA_SHA3_384 = 30,
    GNUTLS_SIGN_RSA_SHA3_512 = 31,

    GNUTLS_SIGN_RSA_PSS_SHA256 = 32,
    GNUTLS_SIGN_RSA_PSS_SHA384 = 33,
    GNUTLS_SIGN_RSA_PSS_SHA512 = 34,
    GNUTLS_SIGN_EDDSA_ED25519 = 35,
    GNUTLS_SIGN_RSA_RAW = 36,

    GNUTLS_SIGN_ECDSA_SECP256R1_SHA256 = 37,
    GNUTLS_SIGN_ECDSA_SECP384R1_SHA384 = 38,
    GNUTLS_SIGN_ECDSA_SECP521R1_SHA512 = 39,

    GNUTLS_SIGN_RSA_PSS_RSAE_SHA256 = 40,
    GNUTLS_SIGN_RSA_PSS_RSAE_SHA384 = 41,
    GNUTLS_SIGN_RSA_PSS_RSAE_SHA512 = 42,

    GNUTLS_SIGN_GOST_94 = 43,
    GNUTLS_SIGN_GOST_256 = 44,
    GNUTLS_SIGN_GOST_512 = 45,
    GNUTLS_SIGN_EDDSA_ED448 = 46,
    GNUTLS_SIGN_MAX = GNUTLS_SIGN_EDDSA_ED448
}

enum gnutls_ecc_curve_t
{
    GNUTLS_ECC_CURVE_INVALID = 0,
    GNUTLS_ECC_CURVE_SECP224R1 = 1,
    GNUTLS_ECC_CURVE_SECP256R1 = 2,
    GNUTLS_ECC_CURVE_SECP384R1 = 3,
    GNUTLS_ECC_CURVE_SECP521R1 = 4,
    GNUTLS_ECC_CURVE_SECP192R1 = 5,
    GNUTLS_ECC_CURVE_X25519 = 6,
    GNUTLS_ECC_CURVE_ED25519 = 7,
    GNUTLS_ECC_CURVE_GOST256CPA = 8,
    GNUTLS_ECC_CURVE_GOST256CPB = 9,
    GNUTLS_ECC_CURVE_GOST256CPC = 10,
    GNUTLS_ECC_CURVE_GOST256CPXA = 11,
    GNUTLS_ECC_CURVE_GOST256CPXB = 12,
    GNUTLS_ECC_CURVE_GOST512A = 13,
    GNUTLS_ECC_CURVE_GOST512B = 14,
    GNUTLS_ECC_CURVE_GOST512C = 15,
    GNUTLS_ECC_CURVE_GOST256A = 16,
    GNUTLS_ECC_CURVE_GOST256B = 17,
    GNUTLS_ECC_CURVE_GOST256C = 18,
    GNUTLS_ECC_CURVE_GOST256D = 19,
    GNUTLS_ECC_CURVE_X448 = 20,
    GNUTLS_ECC_CURVE_ED448 = 21,
    GNUTLS_ECC_CURVE_MAX = GNUTLS_ECC_CURVE_ED448
}

enum gnutls_group_t
{
    GNUTLS_GROUP_INVALID = 0,
    GNUTLS_GROUP_SECP192R1 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_SECP192R1,
    GNUTLS_GROUP_SECP224R1 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_SECP224R1,
    GNUTLS_GROUP_SECP256R1 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_SECP256R1,
    GNUTLS_GROUP_SECP384R1 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_SECP384R1,
    GNUTLS_GROUP_SECP521R1 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_SECP521R1,
    GNUTLS_GROUP_X25519 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_X25519,
    GNUTLS_GROUP_X448 = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_X448,

    GNUTLS_GROUP_GC256A = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST256A,
    GNUTLS_GROUP_GC256B = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST256B,
    GNUTLS_GROUP_GC256C = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST256C,
    GNUTLS_GROUP_GC256D = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST256D,
    GNUTLS_GROUP_GC512A = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST512A,
    GNUTLS_GROUP_GC512B = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST512B,
    GNUTLS_GROUP_GC512C = gnutls_ecc_curve_t.GNUTLS_ECC_CURVE_GOST512C,

    GNUTLS_GROUP_FFDHE2048 = 256,
    GNUTLS_GROUP_FFDHE3072 = 257,
    GNUTLS_GROUP_FFDHE4096 = 258,
    GNUTLS_GROUP_FFDHE8192 = 259,
    GNUTLS_GROUP_FFDHE6144 = 260,
    GNUTLS_GROUP_MAX = GNUTLS_GROUP_FFDHE6144
}

enum gnutls_sec_param_t
{
    GNUTLS_SEC_PARAM_UNKNOWN = 0,
    GNUTLS_SEC_PARAM_INSECURE = 5,
    GNUTLS_SEC_PARAM_EXPORT = 10,
    GNUTLS_SEC_PARAM_VERY_WEAK = 15,
    GNUTLS_SEC_PARAM_WEAK = 20,
    GNUTLS_SEC_PARAM_LOW = 25,
    GNUTLS_SEC_PARAM_LEGACY = 30,
    GNUTLS_SEC_PARAM_MEDIUM = 35,
    GNUTLS_SEC_PARAM_HIGH = 40,
    GNUTLS_SEC_PARAM_ULTRA = 45,
    GNUTLS_SEC_PARAM_FUTURE = 50,
    GNUTLS_SEC_PARAM_MAX = GNUTLS_SEC_PARAM_FUTURE
}

enum gnutls_channel_binding_t
{
    GNUTLS_CB_TLS_UNIQUE = 0
}

enum gnutls_gost_paramset_t
{
    GNUTLS_GOST_PARAMSET_UNKNOWN = 0,
    GNUTLS_GOST_PARAMSET_TC26_Z = 1,
    GNUTLS_GOST_PARAMSET_CP_A = 2,
    GNUTLS_GOST_PARAMSET_CP_B = 3,
    GNUTLS_GOST_PARAMSET_CP_C = 4,
    GNUTLS_GOST_PARAMSET_CP_D = 5
}

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
{
    enum gnutls_ctype_target_t
    {
        GNUTLS_CTYPE_CLIENT = 0,
        GNUTLS_CTYPE_SERVER = 1,
        GNUTLS_CTYPE_OURS = 2,
        GNUTLS_CTYPE_PEERS = 3
    }
}

alias gnutls_transport_ptr_t = void*;

struct gnutls_session_int;
alias gnutls_session_t = gnutls_session_int*;

struct gnutls_dh_params_int;
alias gnutls_dh_params_t = gnutls_dh_params_int*;

struct gnutls_x509_privkey_int;
alias gnutls_rsa_params_t = gnutls_x509_privkey_int*;

struct gnutls_priority_st;
alias gnutls_priority_t = gnutls_priority_st*;

struct gnutls_datum_t
{
    ubyte* data;
    uint size;
}

struct gnutls_params_st
{
    gnutls_params_type_t type;

    union params_t
    {
        gnutls_dh_params_t dh;
        gnutls_rsa_params_t rsa_export;
    }

    params_t params;
    int deinit;
}

struct gnutls_range_st
{
    size_t low;
    size_t high;
}

struct mbuffer_st;
alias gnutls_packet_t = mbuffer_st*;

enum gnutls_server_name_type_t
{
    GNUTLS_NAME_DNS = 1
}

enum gnutls_session_flags_t
{
    GNUTLS_SFLAGS_SAFE_RENEGOTIATION = 1,
    GNUTLS_SFLAGS_EXT_MASTER_SECRET = 1 << 1,
    GNUTLS_SFLAGS_ETM = 1 << 2,
    GNUTLS_SFLAGS_HB_LOCAL_SEND = 1 << 3,
    GNUTLS_SFLAGS_HB_PEER_SEND = 1 << 4,
    GNUTLS_SFLAGS_FALSE_START = 1 << 5,
    GNUTLS_SFLAGS_RFC7919 = 1 << 6, /// Available from GnuTLS 3.6.0
    GNUTLS_SFLAGS_SESSION_TICKET = 1 << 7,
    GNUTLS_SFLAGS_POST_HANDSHAKE_AUTH = 1 << 8,
    GNUTLS_SFLAGS_EARLY_START = 1 << 9,
    GNUTLS_SFLAGS_EARLY_DATA = 1 << 10,
    GNUTLS_SFLAGS_CLI_REQUESTED_OCSP = 1 << 11, /// Available from GnuTLS 3.6.12
    GNUTLS_SFLAGS_SERV_REQUESTED_OCSP = 1 << 12 /// Available from GnuTLS 3.6.12
}

enum gnutls_supplemental_data_format_type_t
{
    GNUTLS_SUPPLEMENTAL_UNKNOWN = 0
}

enum gnutls_srtp_profile_t
{
    GNUTLS_SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001,
    GNUTLS_SRTP_AES128_CM_HMAC_SHA1_32 = 0x0002,
    GNUTLS_SRTP_NULL_HMAC_SHA1_80 = 0x0005,
    GNUTLS_SRTP_NULL_HMAC_SHA1_32 = 0x0006
}

enum gnutls_alpn_flags_t
{
    GNUTLS_ALPN_MANDATORY = 1,
    GNUTLS_ALPN_SERVER_PRECEDENCE = 1 << 1
}

enum gnutls_vdata_types_t
{
    GNUTLS_DT_UNKNOWN = 0,
    GNUTLS_DT_DNS_HOSTNAME = 1,
    GNUTLS_DT_KEY_PURPOSE_OID = 2,
    GNUTLS_DT_RFC822NAME = 3,
    GNUTLS_DT_IP_ADDRESS = 4 /// Available from GnuTLS 3.6.0
}

struct gnutls_typed_vdata_st
{
    gnutls_vdata_types_t type;
    ubyte* data;
    uint size;
}

struct gnutls_pubkey_st;
alias gnutls_pubkey_t = gnutls_pubkey_st*;

struct gnutls_privkey_st;
alias gnutls_privkey_t = gnutls_privkey_st*;

alias gnutls_x509_privkey_t = gnutls_x509_privkey_int*;

struct gnutls_x509_crl_int;
alias gnutls_x509_crl_t = gnutls_x509_crl_int*;

struct gnutls_x509_crt_int;
alias gnutls_x509_crt_t = gnutls_x509_crt_int*;

struct gnutls_x509_crq_int;
alias gnutls_x509_crq_t = gnutls_x509_crq_int*;

struct gnutls_openpgp_keyring_int;
alias gnutls_openpgp_keyring_t = gnutls_openpgp_keyring_int*;

struct gnutls_certificate_credentials_st;
alias gnutls_certificate_credentials_t = gnutls_certificate_credentials_st*;
alias gnutls_certificate_server_credentials = gnutls_certificate_credentials_st*;
alias gnutls_certificate_client_credentials = gnutls_certificate_credentials_st*;

struct gnutls_anon_server_credentials_st;
alias gnutls_anon_server_credentials_t = gnutls_anon_server_credentials_st*;
struct gnutls_anon_client_credentials_st;
alias gnutls_anon_client_credentials_t = gnutls_anon_client_credentials_st*;

enum gnutls_certificate_flags
{
    GNUTLS_CERTIFICATE_SKIP_KEY_CERT_MATCH = 1,
    GNUTLS_CERTIFICATE_API_V2 = 1 << 1, /// Available from GnuTLS 3.5.6
    GNUTLS_CERTIFICATE_SKIP_OCSP_RESPONSE_CHECK = 1 << 2,
    GNUTLS_CERTIFICATE_VERIFY_CRLS = 1 << 3 /// Available from GnuTLS 3.6.4
}

struct gnutls_ocsp_data_st
{
    uint version_;
    gnutls_datum_t response;
    time_t exptime;
    ubyte[32] padding;
}

alias giovec_t = iovec;

enum gnutls_random_art_
{
    GNUTLS_RANDOM_ART_OPENSSH = 1
}

alias gnutls_random_art_t = gnutls_random_art_;

struct gnutls_srp_server_credentials_st;
alias gnutls_srp_server_credentials_t = gnutls_srp_server_credentials_st*;
struct gnutls_srp_client_credentials_st;
alias gnutls_srp_client_credentials_t = gnutls_srp_client_credentials_st*;

struct gnutls_psk_server_credentials_st;
alias gnutls_psk_server_credentials_t = gnutls_psk_server_credentials_st*;
struct gnutls_psk_client_credentials_st;
alias gnutls_psk_client_credentials_t = gnutls_psk_client_credentials_st*;

enum gnutls_psk_key_flags
{
    GNUTLS_PSK_KEY_RAW = 0,
    GNUTLS_PSK_KEY_HEX = 1
}

enum gnutls_x509_subject_alt_name_t
{
    GNUTLS_SAN_DNSNAME = 1,
    GNUTLS_SAN_RFC822NAME = 2,
    GNUTLS_SAN_URI = 3,
    GNUTLS_SAN_IPADDRESS = 4,
    GNUTLS_SAN_OTHERNAME = 5,
    GNUTLS_SAN_DN = 6,
    GNUTLS_SAN_REGISTERED_ID = 7, /// Available from GnuTLS 3.6.9
    GNUTLS_SAN_MAX = GNUTLS_SAN_REGISTERED_ID,

    GNUTLS_SAN_OTHERNAME_XMPP = 1000,
    GNUTLS_SAN_OTHERNAME_KRB5PRINCIPAL = 1001
}

struct gnutls_openpgp_crt_int;
alias gnutls_openpgp_crt_t = gnutls_openpgp_crt_int*;

struct gnutls_openpgp_privkey_int;
alias gnutls_openpgp_privkey_t = gnutls_openpgp_privkey_int*;

struct gnutls_pkcs11_privkey_st;
alias gnutls_pkcs11_privkey_t = gnutls_pkcs11_privkey_st*;

enum gnutls_privkey_type_t
{
    GNUTLS_PRIVKEY_X509 = 0,
    GNUTLS_PRIVKEY_OPENPGP = 1,
    GNUTLS_PRIVKEY_PKCS11 = 2,
    GNUTLS_PRIVKEY_EXT = 3
}

struct gnutls_retr2_st
{
    gnutls_certificate_type_t cert_type;
    gnutls_privkey_type_t key_type;

    union _Anonymous_0
    {
        gnutls_x509_crt_t* x509;
        gnutls_openpgp_crt_t pgp;
    }

    _Anonymous_0 cert;
    uint ncerts;

    union _Anonymous_1
    {
        gnutls_x509_privkey_t x509;
        gnutls_openpgp_privkey_t pgp;
        gnutls_pkcs11_privkey_t pkcs11;
    }

    _Anonymous_1 key;

    uint deinit_all;
}

struct gnutls_tdb_int;
alias gnutls_tdb_t = gnutls_tdb_int*;

enum gnutls_pin_flag_t
{
    GNUTLS_PIN_USER = 1 << 0,
    GNUTLS_PIN_SO = 1 << 1,
    GNUTLS_PIN_FINAL_TRY = 1 << 2,
    GNUTLS_PIN_COUNT_LOW = 1 << 3,
    GNUTLS_PIN_CONTEXT_SPECIFIC = 1 << 4,
    GNUTLS_PIN_WRONG = 1 << 5
}

struct gnutls_buffer_st;
alias gnutls_ext_priv_data_t = void*;

enum gnutls_ext_parse_type_t
{
    GNUTLS_EXT_ANY = 0,
    GNUTLS_EXT_APPLICATION = 1,
    GNUTLS_EXT_TLS = 2,
    GNUTLS_EXT_MANDATORY = 3,
    GNUTLS_EXT_NONE = 4,
    GNUTLS_EXT_VERSION_NEG = 5
}

enum gnutls_ext_flags_t
{
    GNUTLS_EXT_FLAG_OVERRIDE_INTERNAL = 1,
    GNUTLS_EXT_FLAG_CLIENT_HELLO = 1 << 1,
    GNUTLS_EXT_FLAG_TLS12_SERVER_HELLO = 1 << 2,
    GNUTLS_EXT_FLAG_TLS13_SERVER_HELLO = 1 << 3,
    GNUTLS_EXT_FLAG_EE = 1 << 4,
    GNUTLS_EXT_FLAG_HRR = 1 << 5,
    GNUTLS_EXT_FLAG_IGNORE_CLIENT_REQUEST = 1 << 6,
    GNUTLS_EXT_FLAG_TLS = 1 << 7,
    GNUTLS_EXT_FLAG_DTLS = 1 << 8
}

struct gnutls_anti_replay_st;
alias gnutls_anti_replay_t = gnutls_anti_replay_st*;

enum gnutls_fips_mode_t
{
    GNUTLS_FIPS140_DISABLED = 0,
    GNUTLS_FIPS140_STRICT = 1,
    GNUTLS_FIPS140_SELFTESTS = 2,
    GNUTLS_FIPS140_LAX = 3,
    GNUTLS_FIPS140_LOG = 4
}
enum GNUTLS_VERSION = "3.6.15";
enum GNUTLS_VERSION_MAJOR = 3;
enum GNUTLS_VERSION_MINOR = 6;
enum GNUTLS_VERSION_PATCH = 15;
enum GNUTLS_VERSION_NUMBER = 0x03060f;
enum GNUTLS_CIPHER_RIJNDAEL_128_CBC = gnutls_cipher_algorithm_t.GNUTLS_CIPHER_AES_128_CBC;
enum GNUTLS_CIPHER_RIJNDAEL_256_CBC = gnutls_cipher_algorithm_t.GNUTLS_CIPHER_AES_256_CBC;
enum GNUTLS_CIPHER_RIJNDAEL_CBC = gnutls_cipher_algorithm_t.GNUTLS_CIPHER_AES_128_CBC;
enum GNUTLS_CIPHER_ARCFOUR = gnutls_cipher_algorithm_t.GNUTLS_CIPHER_ARCFOUR_128;
enum GNUTLS_MAC_SHA = gnutls_mac_algorithm_t.GNUTLS_MAC_SHA1;
enum GNUTLS_DIG_SHA = gnutls_digest_algorithm_t.GNUTLS_DIG_SHA1;
enum GNUTLS_MAX_ALGORITHM_NUM = 64;
enum GNUTLS_MAX_SESSION_ID_SIZE = 32;
enum GNUTLS_SERVER = 1;
enum GNUTLS_CLIENT = 1 << 1;
enum GNUTLS_DATAGRAM = 1 << 2;
enum GNUTLS_NONBLOCK = 1 << 3;
enum GNUTLS_NO_EXTENSIONS = 1 << 4;
enum GNUTLS_NO_REPLAY_PROTECTION = 1 << 5;
enum GNUTLS_NO_SIGNAL = 1 << 6;
enum GNUTLS_ALLOW_ID_CHANGE = 1 << 7;
enum GNUTLS_ENABLE_FALSE_START = 1 << 8;
enum GNUTLS_FORCE_CLIENT_CERT = 1 << 9;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
    enum GNUTLS_NO_TICKETS = 1 << 10;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4 && gnuTLSSupport < GnuTLSSupport.gnutls_3_6_6)
    enum GNUTLS_ENABLE_CERT_TYPE_NEG = 0;

enum GNUTLS_HANDSHAKE_ANY = cast(uint) -1;
enum GNUTLS_CRT_RAW = gnutls_certificate_type_t.GNUTLS_CRT_RAWPK;
enum GNUTLS_PK_ECC = gnutls_pk_algorithm_t.GNUTLS_PK_ECDSA;
enum GNUTLS_PK_EC = gnutls_pk_algorithm_t.GNUTLS_PK_ECDSA;
enum GNUTLS_PK_ECDHX = gnutls_pk_algorithm_t.GNUTLS_PK_ECDH_X25519;

enum GNUTLS_SEC_PARAM_NORMAL = gnutls_sec_param_t.GNUTLS_SEC_PARAM_MEDIUM;
alias _gnutls_deinit = gnutls_deinit;
enum GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT = cast(uint) -1;
enum GNUTLS_INDEFINITE_TIMEOUT = cast(uint) -2;
enum GNUTLS_KU_PEER = 1;
enum GNUTLS_SIGN_FLAG_SECURE_FOR_CERTS = 1;
alias gnutls_sign_algorithm_get_name = gnutls_sign_get_name;
enum GNUTLS_HEARTBEAT_WAIT = 1;
enum GNUTLS_RECORD_WAIT = 1;
alias gnutls_read = gnutls_record_recv;
alias gnutls_write = gnutls_record_send;
enum GNUTLS_HB_PEER_ALLOWED_TO_SEND = 1;
enum GNUTLS_HB_PEER_NOT_ALLOWED_TO_SEND = 1 << 1;
enum GNUTLS_HB_LOCAL_ALLOWED_TO_SEND = 1 << 2;
enum GNUTLS_ALPN_MAND = gnutls_alpn_flags_t.GNUTLS_ALPN_MANDATORY;
enum GNUTLS_PRIORITY_INIT_DEF_APPEND = 1;
enum GNUTLS_PRIORITY_LIST_INIT_KEYWORDS = 1;
enum GNUTLS_PRIORITY_LIST_SPECIAL = 2;
enum GNUTLS_MAX_SESSION_ID = 32;
enum GNUTLS_HOOK_POST = 1;
enum GNUTLS_HOOK_PRE = 0;
enum GNUTLS_HOOK_BOTH = -1;
alias gnutls_handshake_post_client_hello_func = gnutls_handshake_simple_hook_func;

alias gnutls_cred_set = gnutls_credentials_set;
enum GNUTLS_OCSP_SR_IS_AVAIL = 1;

enum GNUTLS_IDNA_FORCE_2008 = 1 << 1;
alias gnutls_srp_base64_encode_alloc = gnutls_srp_base64_encode2;
alias gnutls_srp_base64_decode_alloc = gnutls_srp_base64_decode2;
alias gnutls_pem_base64_encode_alloc = gnutls_pem_base64_encode2;
alias gnutls_pem_base64_decode_alloc = gnutls_pem_base64_decode2;
enum GNUTLS_KEY_DIGITAL_SIGNATURE = 128;
enum GNUTLS_KEY_NON_REPUDIATION = 64;
enum GNUTLS_KEY_KEY_ENCIPHERMENT = 32;
enum GNUTLS_KEY_DATA_ENCIPHERMENT = 16;
enum GNUTLS_KEY_KEY_AGREEMENT = 8;
enum GNUTLS_KEY_KEY_CERT_SIGN = 4;
enum GNUTLS_KEY_CRL_SIGN = 2;
enum GNUTLS_KEY_ENCIPHER_ONLY = 1;
enum GNUTLS_KEY_DECIPHER_ONLY = 32768;
enum GNUTLS_SCOMMIT_FLAG_ALLOW_BROKEN = 1;
enum GNUTLS_PKCS11_PIN_USER = gnutls_pin_flag_t.GNUTLS_PIN_USER;
enum GNUTLS_PKCS11_PIN_SO = gnutls_pin_flag_t.GNUTLS_PIN_SO;
enum GNUTLS_PKCS11_PIN_FINAL_TRY = gnutls_pin_flag_t.GNUTLS_PIN_FINAL_TRY;
enum GNUTLS_PKCS11_PIN_COUNT_LOW = gnutls_pin_flag_t.GNUTLS_PIN_COUNT_LOW;
enum GNUTLS_PKCS11_PIN_CONTEXT_SPECIFIC = gnutls_pin_flag_t.GNUTLS_PIN_CONTEXT_SPECIFIC;
enum GNUTLS_PKCS11_PIN_WRONG = gnutls_pin_flag_t.GNUTLS_PIN_WRONG;
enum GNUTLS_UTF8_IGNORE_ERRS = 1;
enum GNUTLS_EXT_RAW_FLAG_TLS_CLIENT_HELLO = 1;
enum GNUTLS_EXT_RAW_FLAG_DTLS_CLIENT_HELLO = 1 << 1;
enum GNUTLS_FIPS140_SET_MODE_THREAD = 1;

enum GNUTLS_E_SUCCESS = 0;
enum GNUTLS_E_UNKNOWN_COMPRESSION_ALGORITHM = -3;
enum GNUTLS_E_UNKNOWN_CIPHER_TYPE = -6;
enum GNUTLS_E_LARGE_PACKET = -7;
enum GNUTLS_E_UNSUPPORTED_VERSION_PACKET = -8;
enum GNUTLS_E_TLS_PACKET_DECODING_ERROR = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
enum GNUTLS_E_UNEXPECTED_PACKET_LENGTH = -9;
enum GNUTLS_E_INVALID_SESSION = -10;
enum GNUTLS_E_FATAL_ALERT_RECEIVED = -12;
enum GNUTLS_E_UNEXPECTED_PACKET = -15;
enum GNUTLS_E_WARNING_ALERT_RECEIVED = -16;
enum GNUTLS_E_ERROR_IN_FINISHED_PACKET = -18;
enum GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET = -19;
enum GNUTLS_E_UNKNOWN_CIPHER_SUITE = -21;
enum GNUTLS_E_UNWANTED_ALGORITHM = -22;
enum GNUTLS_E_MPI_SCAN_FAILED = -23;
enum GNUTLS_E_DECRYPTION_FAILED = -24;
enum GNUTLS_E_MEMORY_ERROR = -25;
enum GNUTLS_E_DECOMPRESSION_FAILED = -26;
enum GNUTLS_E_COMPRESSION_FAILED = -27;
enum GNUTLS_E_AGAIN = -28;
enum GNUTLS_E_EXPIRED = -29;
enum GNUTLS_E_DB_ERROR = -30;
enum GNUTLS_E_SRP_PWD_ERROR = GNUTLS_E_KEYFILE_ERROR;
enum GNUTLS_E_KEYFILE_ERROR = -31;
enum GNUTLS_E_INSUFFICIENT_CREDENTIALS = -32;
enum GNUTLS_E_INSUFICIENT_CREDENTIALS = GNUTLS_E_INSUFFICIENT_CREDENTIALS;
enum GNUTLS_E_INSUFFICIENT_CRED = GNUTLS_E_INSUFFICIENT_CREDENTIALS;
enum GNUTLS_E_INSUFICIENT_CRED = GNUTLS_E_INSUFFICIENT_CREDENTIALS;

enum GNUTLS_E_HASH_FAILED = -33;
enum GNUTLS_E_BASE64_DECODING_ERROR = -34;

enum GNUTLS_E_MPI_PRINT_FAILED = -35;
enum GNUTLS_E_REHANDSHAKE = -37;
enum GNUTLS_E_GOT_APPLICATION_DATA = -38;
enum GNUTLS_E_RECORD_LIMIT_REACHED = -39;
enum GNUTLS_E_ENCRYPTION_FAILED = -40;

enum GNUTLS_E_PK_ENCRYPTION_FAILED = -44;
enum GNUTLS_E_PK_DECRYPTION_FAILED = -45;
enum GNUTLS_E_PK_SIGN_FAILED = -46;
enum GNUTLS_E_X509_UNSUPPORTED_CRITICAL_EXTENSION = -47;
enum GNUTLS_E_KEY_USAGE_VIOLATION = -48;
enum GNUTLS_E_NO_CERTIFICATE_FOUND = -49;
enum GNUTLS_E_INVALID_REQUEST = -50;
enum GNUTLS_E_SHORT_MEMORY_BUFFER = -51;
enum GNUTLS_E_INTERRUPTED = -52;
enum GNUTLS_E_PUSH_ERROR = -53;
enum GNUTLS_E_PULL_ERROR = -54;
enum GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER = -55;
enum GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE = -56;
enum GNUTLS_E_PKCS1_WRONG_PAD = -57;
enum GNUTLS_E_RECEIVED_ILLEGAL_EXTENSION = -58;
enum GNUTLS_E_INTERNAL_ERROR = -59;
enum GNUTLS_E_DH_PRIME_UNACCEPTABLE = -63;
enum GNUTLS_E_FILE_ERROR = -64;
enum GNUTLS_E_TOO_MANY_EMPTY_PACKETS = -78;
enum GNUTLS_E_UNKNOWN_PK_ALGORITHM = -80;
enum GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS = -81;
enum GNUTLS_E_RECEIVED_DISALLOWED_NAME = -82;
enum GNUTLS_E_CERTIFICATE_REQUIRED = -112;

enum GNUTLS_E_NO_TEMPORARY_RSA_PARAMS = -84;

enum GNUTLS_E_NO_COMPRESSION_ALGORITHMS = -86;
enum GNUTLS_E_NO_CIPHER_SUITES = -87;

enum GNUTLS_E_OPENPGP_GETKEY_FAILED = -88;
enum GNUTLS_E_PK_SIG_VERIFY_FAILED = -89;

enum GNUTLS_E_ILLEGAL_SRP_USERNAME = -90;
enum GNUTLS_E_SRP_PWD_PARSING_ERROR = GNUTLS_E_KEYFILE_PARSING_ERROR;
enum GNUTLS_E_KEYFILE_PARSING_ERROR = -91;
enum GNUTLS_E_NO_TEMPORARY_DH_PARAMS = -93;

enum GNUTLS_E_ASN1_ELEMENT_NOT_FOUND = -67;
enum GNUTLS_E_ASN1_IDENTIFIER_NOT_FOUND = -68;
enum GNUTLS_E_ASN1_DER_ERROR = -69;
enum GNUTLS_E_ASN1_VALUE_NOT_FOUND = -70;
enum GNUTLS_E_ASN1_GENERIC_ERROR = -71;
enum GNUTLS_E_ASN1_VALUE_NOT_VALID = -72;
enum GNUTLS_E_ASN1_TAG_ERROR = -73;
enum GNUTLS_E_ASN1_TAG_IMPLICIT = -74;
enum GNUTLS_E_ASN1_TYPE_ANY_ERROR = -75;
enum GNUTLS_E_ASN1_SYNTAX_ERROR = -76;
enum GNUTLS_E_ASN1_DER_OVERFLOW = -77;
enum GNUTLS_E_OPENPGP_UID_REVOKED = -79;
enum GNUTLS_E_CERTIFICATE_ERROR = -43;
enum GNUTLS_E_X509_CERTIFICATE_ERROR = GNUTLS_E_CERTIFICATE_ERROR;
enum GNUTLS_E_CERTIFICATE_KEY_MISMATCH = -60;
enum GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE = -61;
enum GNUTLS_E_X509_UNKNOWN_SAN = -62;
enum GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED = -94;
enum GNUTLS_E_X509_UNSUPPORTED_ATTRIBUTE = -95;
enum GNUTLS_E_UNKNOWN_HASH_ALGORITHM = -96;
enum GNUTLS_E_UNKNOWN_PKCS_CONTENT_TYPE = -97;
enum GNUTLS_E_UNKNOWN_PKCS_BAG_TYPE = -98;
enum GNUTLS_E_INVALID_PASSWORD = -99;
enum GNUTLS_E_MAC_VERIFY_FAILED = -100;
enum GNUTLS_E_CONSTRAINT_ERROR = -101;

enum GNUTLS_E_WARNING_IA_IPHF_RECEIVED = -102;
enum GNUTLS_E_WARNING_IA_FPHF_RECEIVED = -103;

enum GNUTLS_E_IA_VERIFY_FAILED = -104;
enum GNUTLS_E_UNKNOWN_ALGORITHM = -105;
enum GNUTLS_E_UNSUPPORTED_SIGNATURE_ALGORITHM = -106;
enum GNUTLS_E_SAFE_RENEGOTIATION_FAILED = -107;
enum GNUTLS_E_UNSAFE_RENEGOTIATION_DENIED = -108;
enum GNUTLS_E_UNKNOWN_SRP_USERNAME = -109;
enum GNUTLS_E_PREMATURE_TERMINATION = -110;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
    enum GNUTLS_E_MALFORMED_CIDR = -111;

enum GNUTLS_E_BASE64_ENCODING_ERROR = -201;
enum GNUTLS_E_INCOMPATIBLE_GCRYPT_LIBRARY = -202;
enum GNUTLS_E_INCOMPATIBLE_CRYPTO_LIBRARY = -202;
enum GNUTLS_E_INCOMPATIBLE_LIBTASN1_LIBRARY = -203;

enum GNUTLS_E_OPENPGP_KEYRING_ERROR = -204;
enum GNUTLS_E_X509_UNSUPPORTED_OID = -205;

enum GNUTLS_E_RANDOM_FAILED = -206;
enum GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR = -207;

enum GNUTLS_E_OPENPGP_SUBKEY_ERROR = -208;

enum GNUTLS_E_CRYPTO_ALREADY_REGISTERED = GNUTLS_E_ALREADY_REGISTERED;
enum GNUTLS_E_ALREADY_REGISTERED = -209;

enum GNUTLS_E_HANDSHAKE_TOO_LARGE = -210;

enum GNUTLS_E_CRYPTODEV_IOCTL_ERROR = -211;
enum GNUTLS_E_CRYPTODEV_DEVICE_ERROR = -212;

enum GNUTLS_E_CHANNEL_BINDING_NOT_AVAILABLE = -213;
enum GNUTLS_E_BAD_COOKIE = -214;
enum GNUTLS_E_OPENPGP_PREFERRED_KEY_ERROR = -215;
enum GNUTLS_E_INCOMPAT_DSA_KEY_WITH_TLS_PROTOCOL = -216;
enum GNUTLS_E_INSUFFICIENT_SECURITY = -217;

enum GNUTLS_E_HEARTBEAT_PONG_RECEIVED = -292;
enum GNUTLS_E_HEARTBEAT_PING_RECEIVED = -293;

enum GNUTLS_E_UNRECOGNIZED_NAME = -294;

enum GNUTLS_E_PKCS11_ERROR = -300;
enum GNUTLS_E_PKCS11_LOAD_ERROR = -301;
enum GNUTLS_E_PARSING_ERROR = -302;
enum GNUTLS_E_PKCS11_PIN_ERROR = -303;

enum GNUTLS_E_PKCS11_SLOT_ERROR = -305;
enum GNUTLS_E_LOCKING_ERROR = -306;
enum GNUTLS_E_PKCS11_ATTRIBUTE_ERROR = -307;
enum GNUTLS_E_PKCS11_DEVICE_ERROR = -308;
enum GNUTLS_E_PKCS11_DATA_ERROR = -309;
enum GNUTLS_E_PKCS11_UNSUPPORTED_FEATURE_ERROR = -310;
enum GNUTLS_E_PKCS11_KEY_ERROR = -311;
enum GNUTLS_E_PKCS11_PIN_EXPIRED = -312;
enum GNUTLS_E_PKCS11_PIN_LOCKED = -313;
enum GNUTLS_E_PKCS11_SESSION_ERROR = -314;
enum GNUTLS_E_PKCS11_SIGNATURE_ERROR = -315;
enum GNUTLS_E_PKCS11_TOKEN_ERROR = -316;
enum GNUTLS_E_PKCS11_USER_ERROR = -317;

enum GNUTLS_E_CRYPTO_INIT_FAILED = -318;
enum GNUTLS_E_TIMEDOUT = -319;
enum GNUTLS_E_USER_ERROR = -320;
enum GNUTLS_E_ECC_NO_SUPPORTED_CURVES = -321;
enum GNUTLS_E_ECC_UNSUPPORTED_CURVE = -322;
enum GNUTLS_E_PKCS11_REQUESTED_OBJECT_NOT_AVAILBLE = -323;
enum GNUTLS_E_CERTIFICATE_LIST_UNSORTED = -324;
enum GNUTLS_E_ILLEGAL_PARAMETER = -325;
enum GNUTLS_E_NO_PRIORITIES_WERE_SET = -326;
enum GNUTLS_E_X509_UNSUPPORTED_EXTENSION = -327;
enum GNUTLS_E_SESSION_EOF = -328;

enum GNUTLS_E_TPM_ERROR = -329;
enum GNUTLS_E_TPM_KEY_PASSWORD_ERROR = -330;
enum GNUTLS_E_TPM_SRK_PASSWORD_ERROR = -331;
enum GNUTLS_E_TPM_SESSION_ERROR = -332;
enum GNUTLS_E_TPM_KEY_NOT_FOUND = -333;
enum GNUTLS_E_TPM_UNINITIALIZED = -334;
enum GNUTLS_E_TPM_NO_LIB = -335;

enum GNUTLS_E_NO_CERTIFICATE_STATUS = -340;
enum GNUTLS_E_OCSP_RESPONSE_ERROR = -341;
enum GNUTLS_E_RANDOM_DEVICE_ERROR = -342;
enum GNUTLS_E_AUTH_ERROR = -343;
enum GNUTLS_E_NO_APPLICATION_PROTOCOL = -344;
enum GNUTLS_E_SOCKETS_INIT_ERROR = -345;
enum GNUTLS_E_KEY_IMPORT_FAILED = -346;
enum GNUTLS_E_INAPPROPRIATE_FALLBACK = -347;
enum GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR = -348;
enum GNUTLS_E_PRIVKEY_VERIFICATION_ERROR = -349;
enum GNUTLS_E_UNEXPECTED_EXTENSIONS_LENGTH = -350;
enum GNUTLS_E_ASN1_EMBEDDED_NULL_IN_STRING = -351;

enum GNUTLS_E_SELF_TEST_ERROR = -400;
enum GNUTLS_E_NO_SELF_TEST = -401;
enum GNUTLS_E_LIB_IN_ERROR_STATE = -402;
enum GNUTLS_E_PK_GENERATION_ERROR = -403;
enum GNUTLS_E_IDNA_ERROR = -404;

enum GNUTLS_E_NEED_FALLBACK = -405;
enum GNUTLS_E_SESSION_USER_ID_CHANGED = -406;
enum GNUTLS_E_HANDSHAKE_DURING_FALSE_START = -407;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
    enum GNUTLS_E_UNAVAILABLE_DURING_HANDSHAKE = -408;

static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
{
    enum GNUTLS_E_PK_INVALID_PUBKEY = -409;
    enum GNUTLS_E_PK_INVALID_PRIVKEY = -410;
}

enum GNUTLS_E_NOT_YET_ACTIVATED = -411;
enum GNUTLS_E_INVALID_UTF8_STRING = -412;
enum GNUTLS_E_NO_EMBEDDED_DATA = -413;
enum GNUTLS_E_INVALID_UTF8_EMAIL = -414;
enum GNUTLS_E_INVALID_PASSWORD_STRING = -415;
enum GNUTLS_E_CERTIFICATE_TIME_ERROR = -416;
enum GNUTLS_E_RECORD_OVERFLOW = -417;
enum GNUTLS_E_ASN1_TIME_ERROR = -418;
enum GNUTLS_E_INCOMPATIBLE_SIG_WITH_KEY = -419;
enum GNUTLS_E_PK_INVALID_PUBKEY_PARAMS = -420;
enum GNUTLS_E_PK_NO_VALIDATION_PARAMS = -421;
enum GNUTLS_E_OCSP_MISMATCH_WITH_CERTS = -422;

enum GNUTLS_E_NO_COMMON_KEY_SHARE = -423;
enum GNUTLS_E_REAUTH_REQUEST = -424;
enum GNUTLS_E_TOO_MANY_MATCHES = -425;
enum GNUTLS_E_CRL_VERIFICATION_ERROR = -426;
enum GNUTLS_E_MISSING_EXTENSION = -427;
enum GNUTLS_E_DB_ENTRY_EXISTS = -428;
enum GNUTLS_E_EARLY_DATA_REJECTED = -429;
enum GNUTLS_E_X509_DUPLICATE_EXTENSION = -430;

enum GNUTLS_E_UNIMPLEMENTED_FEATURE = -1250;

enum GNUTLS_E_INT_RET_0 = -1251;
enum GNUTLS_E_INT_CHECK_AGAIN = -1252;

enum GNUTLS_E_APPLICATION_ERROR_MAX = -65000;
enum GNUTLS_E_APPLICATION_ERROR_MIN = -65500;

extern(C) nothrow @nogc
{
    alias gnutls_params_function = int function (gnutls_session_t, gnutls_params_type_t, gnutls_params_st*);
    alias gnutls_certificate_verify_function = int function (gnutls_session_t);
    alias gnutls_db_store_func = int function (void*, gnutls_datum_t key, gnutls_datum_t data);
    alias gnutls_db_remove_func = int function (void*, gnutls_datum_t key);
    alias gnutls_db_retr_func = gnutls_datum_t function (void*, gnutls_datum_t key);
    alias gnutls_handshake_hook_func = int function (gnutls_session_t, uint htype, uint when, uint incoming, const(gnutls_datum_t)* msg);
    alias gnutls_handshake_simple_hook_func = int function (gnutls_session_t);
    alias gnutls_status_request_ocsp_func = int function (gnutls_session_t session, void* ptr, gnutls_datum_t* ocsp_response);
    alias gnutls_time_func = c_long function (time_t* t);
    alias mutex_init_func = int function (void** mutex);
    alias mutex_lock_func = int function (void** mutex);
    alias mutex_unlock_func = int function (void** mutex);
    alias mutex_deinit_func = int function (void** mutex);
    alias gnutls_alloc_function = void* function (size_t);
    alias gnutls_calloc_function = void* function (size_t, size_t);
    alias gnutls_is_secure_function = int function (const(void)*);
    alias gnutls_free_function = void function (void*);
    alias gnutls_realloc_function = void* function (void*, size_t);
    alias gnutls_log_func = void function (int, const(char)*);
    alias gnutls_audit_log_func = void function (gnutls_session_t, const(char)*);
    alias gnutls_keylog_func = int function (gnutls_session_t session, const(char)* label, const(gnutls_datum_t)* secret);
    alias gnutls_pull_func = c_long function (gnutls_transport_ptr_t, void*, size_t);
    alias gnutls_push_func = c_long function (gnutls_transport_ptr_t, const(void)*, size_t);
    alias gnutls_pull_timeout_func = int function (gnutls_transport_ptr_t, uint ms);
    alias gnutls_vec_push_func = c_long function (gnutls_transport_ptr_t, const(giovec_t)* iov, int iovcnt);
    alias gnutls_errno_func = int function (gnutls_transport_ptr_t);
    alias gnutls_srp_server_credentials_function = int function (gnutls_session_t, const(char)* username, gnutls_datum_t* salt, gnutls_datum_t* verifier, gnutls_datum_t* generator, gnutls_datum_t* prime);
    alias gnutls_srp_client_credentials_function = int function (gnutls_session_t, char**, char**);
    alias gnutls_psk_server_credentials_function = int function (gnutls_session_t, const(char)* username, gnutls_datum_t* key);
    alias gnutls_psk_server_credentials_function2 = int function (gnutls_session_t, const(gnutls_datum_t)* username, gnutls_datum_t* key);
    alias gnutls_psk_client_credentials_function = int function (gnutls_session_t, char** username, gnutls_datum_t* key);
    alias gnutls_psk_client_credentials_function2 = int function (gnutls_session_t, gnutls_datum_t* username, gnutls_datum_t* key);
    alias gnutls_certificate_retrieve_function = int function (gnutls_session_t, const(gnutls_datum_t)* req_ca_rdn, int nreqs, const(gnutls_pk_algorithm_t)* pk_algos, int pk_algos_length, gnutls_retr2_st*);
    alias gnutls_tdb_store_func = int function (const(char)* db_name, const(char)* host, const(char)* service, time_t expiration, const(gnutls_datum_t)* pubkey);
    alias gnutls_tdb_store_commitment_func = int function (const(char)* db_name, const(char)* host, const(char)* service, time_t expiration, gnutls_digest_algorithm_t hash_algo, const(gnutls_datum_t)* hash);
    alias gnutls_tdb_verify_func = int function (const(char)* db_name, const(char)* host, const(char)* service, const(gnutls_datum_t)* pubkey);
    alias gnutls_pin_callback_t = int function (void* userdata, int attempt, const(char)* token_url, const(char)* token_label, uint flags, char* pin, size_t pin_max);
    alias gnutls_buffer_t = gnutls_buffer_st*;
    alias gnutls_ext_recv_func = int function (gnutls_session_t session, const(ubyte)* data, size_t len);
    alias gnutls_ext_send_func = int function (gnutls_session_t session, gnutls_buffer_t extdata);
    alias gnutls_ext_deinit_data_func = void function (gnutls_ext_priv_data_t data);
    alias gnutls_ext_pack_func = int function (gnutls_ext_priv_data_t data, gnutls_buffer_t packed_data);
    alias gnutls_ext_unpack_func = int function (gnutls_buffer_t packed_data, gnutls_ext_priv_data_t* data);
    alias gnutls_ext_raw_process_func = int function (void* ctx, uint tls_id, const(ubyte)* data, uint data_size);
    alias gnutls_supp_recv_func = int function (gnutls_session_t session, const(ubyte)* data, size_t data_size);
    alias gnutls_supp_send_func = int function (gnutls_session_t session, gnutls_buffer_t buf);
    alias gnutls_db_add_func = int function (void*, time_t exp_time, const(gnutls_datum_t)* key, const(gnutls_datum_t)* data);
}

extern (D) nothrow @nogc
{
    uint GNUTLS_CURVE_TO_BITS(uint curve) @safe pure
    {
        return cast(uint) (cast(uint) 1 << 31) | (cast(uint) curve);
    }

    uint GNUTLS_BITS_TO_CURVE(uint bits) @safe pure
    {
        return (cast(uint) bits) & 0x7FFFFFFF;
    }

    uint GNUTLS_BITS_ARE_CURVE(uint bits) @safe pure
    {
        return (cast(uint) bits) & 0x80000000;
    }

    const(char)* gnutls_check_version_numeric(uint major, uint minor, uint patch)() @trusted
    {
        enum ver = major.stringof[0..$-1] ~ "." ~ minor.stringof[0..$-1] ~ "." ~ patch.stringof[0..$-1];
        return gnutls_check_version(ver);
    }

    void gnutls_transport_set_int(gnutls_session_t s, int i) @trusted
    {
        gnutls_transport_set_int2(s, i, i);
    }
}

version (BindGnuTLS_Static)
{
    extern (System) extern __gshared
    {
        gnutls_alloc_function gnutls_malloc;
        gnutls_realloc_function gnutls_realloc;
        gnutls_calloc_function gnutls_calloc;
        gnutls_free_function gnutls_free;
        char* function (const(char)*) gnutls_strdup;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_2)
        {
            const gnutls_datum_t gnutls_srp_8192_group_prime;
            const gnutls_datum_t gnutls_srp_8192_group_generator;
        }

        const gnutls_datum_t gnutls_srp_4096_group_prime;
        const gnutls_datum_t gnutls_srp_4096_group_generator;
        const gnutls_datum_t gnutls_srp_3072_group_prime;
        const gnutls_datum_t gnutls_srp_3072_group_generator;
        const gnutls_datum_t gnutls_srp_2048_group_prime;
        const gnutls_datum_t gnutls_srp_2048_group_generator;
        const gnutls_datum_t gnutls_srp_1536_group_prime;
        const gnutls_datum_t gnutls_srp_1536_group_generator;
        const gnutls_datum_t gnutls_srp_1024_group_prime;
        const gnutls_datum_t gnutls_srp_1024_group_generator;
        const gnutls_datum_t gnutls_ffdhe_8192_group_prime;
        const gnutls_datum_t gnutls_ffdhe_8192_group_generator;
        const uint gnutls_ffdhe_8192_key_bits;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
        {
            const gnutls_datum_t gnutls_ffdhe_6144_group_prime;
            const gnutls_datum_t gnutls_ffdhe_6144_group_generator;
            const uint gnutls_ffdhe_6144_key_bits;
        }

        const gnutls_datum_t gnutls_ffdhe_4096_group_prime;
        const gnutls_datum_t gnutls_ffdhe_4096_group_generator;
        const uint gnutls_ffdhe_4096_key_bits;
        const gnutls_datum_t gnutls_ffdhe_3072_group_prime;
        const gnutls_datum_t gnutls_ffdhe_3072_group_generator;
        const uint gnutls_ffdhe_3072_key_bits;
        const gnutls_datum_t gnutls_ffdhe_2048_group_prime;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
        {
            const gnutls_datum_t gnutls_ffdhe_2048_group_q;
            const gnutls_datum_t gnutls_ffdhe_3072_group_q;
            const gnutls_datum_t gnutls_ffdhe_4096_group_q;
            const gnutls_datum_t gnutls_ffdhe_6144_group_q;
            const gnutls_datum_t gnutls_ffdhe_8192_group_q;
        }

        const gnutls_datum_t gnutls_ffdhe_2048_group_generator;
        const uint gnutls_ffdhe_2048_key_bits;
    }

    extern (System) @nogc nothrow @system:

    const(char)* gnutls_pk_algorithm_get_name (gnutls_pk_algorithm_t algorithm);
    int gnutls_init (gnutls_session_t* session, uint flags);
    void gnutls_deinit (gnutls_session_t session);
    int gnutls_bye (gnutls_session_t session, gnutls_close_request_t how);
    int gnutls_handshake (gnutls_session_t session);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_reauth (gnutls_session_t session, uint flags);

    void gnutls_handshake_set_timeout (gnutls_session_t session, uint ms);
    int gnutls_rehandshake (gnutls_session_t session);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_session_key_update (gnutls_session_t session, uint flags);

    gnutls_alert_description_t gnutls_alert_get (gnutls_session_t session);
    int gnutls_alert_send (gnutls_session_t session, gnutls_alert_level_t level, gnutls_alert_description_t desc);
    int gnutls_alert_send_appropriate (gnutls_session_t session, int err);
    const(char)* gnutls_alert_get_name (gnutls_alert_description_t alert);
    const(char)* gnutls_alert_get_strname (gnutls_alert_description_t alert);
    gnutls_sec_param_t gnutls_pk_bits_to_sec_param (gnutls_pk_algorithm_t algo, uint bits);
    const(char)* gnutls_sec_param_get_name (gnutls_sec_param_t param);
    uint gnutls_sec_param_to_pk_bits (gnutls_pk_algorithm_t algo, gnutls_sec_param_t param);
    uint gnutls_sec_param_to_symmetric_bits (gnutls_sec_param_t param);
    const(char)* gnutls_ecc_curve_get_name (gnutls_ecc_curve_t curve);
    const(char)* gnutls_ecc_curve_get_oid (gnutls_ecc_curve_t curve);
    const(char)* gnutls_group_get_name (gnutls_group_t group);
    int gnutls_ecc_curve_get_size (gnutls_ecc_curve_t curve);
    gnutls_ecc_curve_t gnutls_ecc_curve_get (gnutls_session_t session);
    gnutls_group_t gnutls_group_get (gnutls_session_t session);
    gnutls_cipher_algorithm_t gnutls_cipher_get (gnutls_session_t session);
    gnutls_kx_algorithm_t gnutls_kx_get (gnutls_session_t session);
    gnutls_mac_algorithm_t gnutls_mac_get (gnutls_session_t session);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        gnutls_digest_algorithm_t gnutls_prf_hash_get (const gnutls_session_t session);

    gnutls_certificate_type_t gnutls_certificate_type_get (gnutls_session_t session);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
        gnutls_certificate_type_t gnutls_certificate_type_get2 (gnutls_session_t session, gnutls_ctype_target_t target);

    int gnutls_sign_algorithm_get (gnutls_session_t session);
    int gnutls_sign_algorithm_get_client (gnutls_session_t session);
    int gnutls_sign_algorithm_get_requested (gnutls_session_t session, size_t indx, gnutls_sign_algorithm_t* algo);
    const(char)* gnutls_cipher_get_name (gnutls_cipher_algorithm_t algorithm);
    const(char)* gnutls_mac_get_name (gnutls_mac_algorithm_t algorithm);
    const(char)* gnutls_digest_get_name (gnutls_digest_algorithm_t algorithm);
    const(char)* gnutls_digest_get_oid (gnutls_digest_algorithm_t algorithm);
    const(char)* gnutls_kx_get_name (gnutls_kx_algorithm_t algorithm);
    const(char)* gnutls_certificate_type_get_name (gnutls_certificate_type_t type);
    const(char)* gnutls_pk_get_name (gnutls_pk_algorithm_t algorithm);
    const(char)* gnutls_pk_get_oid (gnutls_pk_algorithm_t algorithm);
    const(char)* gnutls_sign_get_name (gnutls_sign_algorithm_t algorithm);
    const(char)* gnutls_sign_get_oid (gnutls_sign_algorithm_t sign);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
    {
        const(char)* gnutls_gost_paramset_get_name (gnutls_gost_paramset_t param);
        const(char)* gnutls_gost_paramset_get_oid (gnutls_gost_paramset_t param);
    }

    size_t gnutls_cipher_get_key_size (gnutls_cipher_algorithm_t algorithm);
    size_t gnutls_mac_get_key_size (gnutls_mac_algorithm_t algorithm);
    uint gnutls_sign_is_secure (gnutls_sign_algorithm_t algorithm);
    uint gnutls_sign_is_secure2 (gnutls_sign_algorithm_t algorithm, uint flags);
    gnutls_digest_algorithm_t gnutls_sign_get_hash_algorithm (gnutls_sign_algorithm_t sign);
    gnutls_pk_algorithm_t gnutls_sign_get_pk_algorithm (gnutls_sign_algorithm_t sign);
    gnutls_sign_algorithm_t gnutls_pk_to_sign (gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash);
    uint gnutls_sign_supports_pk_algorithm (gnutls_sign_algorithm_t sign, gnutls_pk_algorithm_t pk);
    gnutls_mac_algorithm_t gnutls_mac_get_id (const(char)* name);
    gnutls_digest_algorithm_t gnutls_digest_get_id (const(char)* name);
    gnutls_cipher_algorithm_t gnutls_cipher_get_id (const(char)* name);
    gnutls_kx_algorithm_t gnutls_kx_get_id (const(char)* name);
    gnutls_protocol_t gnutls_protocol_get_id (const(char)* name);
    gnutls_certificate_type_t gnutls_certificate_type_get_id (const(char)* name);
    gnutls_pk_algorithm_t gnutls_pk_get_id (const(char)* name);
    gnutls_sign_algorithm_t gnutls_sign_get_id (const(char)* name);
    gnutls_ecc_curve_t gnutls_ecc_curve_get_id (const(char)* name);
    gnutls_pk_algorithm_t gnutls_ecc_curve_get_pk (gnutls_ecc_curve_t curve);
    gnutls_group_t gnutls_group_get_id (const(char)* name);
    gnutls_digest_algorithm_t gnutls_oid_to_digest (const(char)* oid);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
        gnutls_mac_algorithm_t gnutls_oid_to_mac (const(char)* oid);

    gnutls_pk_algorithm_t gnutls_oid_to_pk (const(char)* oid);
    gnutls_sign_algorithm_t gnutls_oid_to_sign (const(char)* oid);
    gnutls_ecc_curve_t gnutls_oid_to_ecc_curve (const(char)* oid);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        gnutls_gost_paramset_t gnutls_oid_to_gost_paramset (const(char)* oid);

    const(gnutls_ecc_curve_t)* gnutls_ecc_curve_list ();
    const(gnutls_group_t)* gnutls_group_list ();
    const(gnutls_cipher_algorithm_t)* gnutls_cipher_list ();
    const(gnutls_mac_algorithm_t)* gnutls_mac_list ();
    const(gnutls_digest_algorithm_t)* gnutls_digest_list ();
    const(gnutls_protocol_t)* gnutls_protocol_list ();
    const(gnutls_certificate_type_t)* gnutls_certificate_type_list ();
    const(gnutls_kx_algorithm_t)* gnutls_kx_list ();
    const(gnutls_pk_algorithm_t)* gnutls_pk_list ();
    const(gnutls_sign_algorithm_t)* gnutls_sign_list ();
    const(char)* gnutls_cipher_suite_info (size_t idx, ubyte* cs_id, gnutls_kx_algorithm_t* kx, gnutls_cipher_algorithm_t* cipher, gnutls_mac_algorithm_t* mac, gnutls_protocol_t* min_version);
    int gnutls_error_is_fatal (int error);
    int gnutls_error_to_alert (int err, int* level);
    void gnutls_perror (int error);
    const(char)* gnutls_strerror (int error);
    const(char)* gnutls_strerror_name (int error);
    void gnutls_handshake_set_private_extensions (gnutls_session_t session, int allow);
    int gnutls_handshake_set_random (gnutls_session_t session, const(gnutls_datum_t)* random);
    gnutls_handshake_description_t gnutls_handshake_get_last_out (gnutls_session_t session);
    gnutls_handshake_description_t gnutls_handshake_get_last_in (gnutls_session_t session);
    int gnutls_heartbeat_ping (gnutls_session_t session, size_t data_size, uint max_tries, uint flags);
    int gnutls_heartbeat_pong (gnutls_session_t session, uint flags);
    void gnutls_record_set_timeout (gnutls_session_t session, uint ms);
    void gnutls_record_disable_padding (gnutls_session_t session);
    void gnutls_record_cork (gnutls_session_t session);
    int gnutls_record_uncork (gnutls_session_t session, uint flags);
    size_t gnutls_record_discard_queued (gnutls_session_t session);
    int gnutls_record_get_state (gnutls_session_t session, uint read, gnutls_datum_t* mac_key, gnutls_datum_t* IV, gnutls_datum_t* cipher_key, ref ubyte[8] seq_number);
    int gnutls_record_set_state (gnutls_session_t session, uint read, ref const(ubyte)[8] seq_number);
    int gnutls_range_split (gnutls_session_t session, const(gnutls_range_st)* orig, gnutls_range_st* small_range, gnutls_range_st* rem_range);
    ssize_t gnutls_record_send (gnutls_session_t session, const(void)* data, size_t data_size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        ssize_t gnutls_record_send2 (gnutls_session_t session, const(void)* data, size_t data_size, size_t pad, uint flags);

    ssize_t gnutls_record_send_range (gnutls_session_t session, const(void)* data, size_t data_size, const(gnutls_range_st)* range);
    ssize_t gnutls_record_recv (gnutls_session_t session, void* data, size_t data_size);
    ssize_t gnutls_record_recv_packet (gnutls_session_t session, gnutls_packet_t* packet);
    void gnutls_packet_get (gnutls_packet_t packet, gnutls_datum_t* data, ubyte* sequence);
    void gnutls_packet_deinit (gnutls_packet_t packet);
    ssize_t gnutls_record_recv_seq (gnutls_session_t session, void* data, size_t data_size, ubyte* seq);
    size_t gnutls_record_overhead_size (gnutls_session_t session);
    size_t gnutls_est_record_overhead_size (gnutls_protocol_t version_, gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac, gnutls_compression_method_t comp, uint flags);
    void gnutls_session_enable_compatibility_mode (gnutls_session_t session);
    uint gnutls_record_can_use_length_hiding (gnutls_session_t session);
    int gnutls_record_get_direction (gnutls_session_t session);
    size_t gnutls_record_get_max_size (gnutls_session_t session);
    ssize_t gnutls_record_set_max_size (gnutls_session_t session, size_t size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
        ssize_t gnutls_record_set_max_recv_size (gnutls_session_t session, size_t size);

    size_t gnutls_record_check_pending (gnutls_session_t session);
    size_t gnutls_record_check_corked (gnutls_session_t session);


    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
        int gnutls_record_set_max_early_data_size (gnutls_session_t session, size_t size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
    {
        size_t gnutls_record_get_max_early_data_size (gnutls_session_t session);
        ssize_t gnutls_record_send_early_data (gnutls_session_t session, const(void)* data, size_t length);
        ssize_t gnutls_record_recv_early_data (gnutls_session_t session, void* data, size_t data_size);
    }

    void gnutls_session_force_valid (gnutls_session_t session);
    int gnutls_prf (gnutls_session_t session, size_t label_size, const(char)* label, int server_random_first, size_t extra_size, const(char)* extra, size_t outsize, char* out_);
    int gnutls_prf_rfc5705 (gnutls_session_t session, size_t label_size, const(char)* label, size_t context_size, const(char)* context, size_t outsize, char* out_);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
        int gnutls_prf_early (gnutls_session_t session, size_t label_size, const(char)* label, size_t context_size, const(char)* context, size_t outsize, char* out_);

    int gnutls_prf_raw (gnutls_session_t session, size_t label_size, const(char)* label, size_t seed_size, const(char)* seed, size_t outsize, char* out_);
    int gnutls_server_name_set (gnutls_session_t session, gnutls_server_name_type_t type, const(void)* name, size_t name_length);
    int gnutls_server_name_get (gnutls_session_t session, void* data, size_t* data_length, uint* type, uint indx);
    uint gnutls_heartbeat_get_timeout (gnutls_session_t session);
    void gnutls_heartbeat_set_timeouts (gnutls_session_t session, uint retrans_timeout, uint total_timeout);
    void gnutls_heartbeat_enable (gnutls_session_t session, uint type);
    uint gnutls_heartbeat_allowed (gnutls_session_t session, uint type);
    uint gnutls_safe_renegotiation_status (gnutls_session_t session);
    uint gnutls_session_ext_master_secret_status (gnutls_session_t session);
    uint gnutls_session_etm_status (gnutls_session_t session);
    uint gnutls_session_get_flags (gnutls_session_t session);
    const(char)* gnutls_supplemental_get_name (gnutls_supplemental_data_format_type_t type);
    int gnutls_session_ticket_key_generate (gnutls_datum_t* key);
    int gnutls_session_ticket_enable_client (gnutls_session_t session);
    int gnutls_session_ticket_enable_server (gnutls_session_t session, const(gnutls_datum_t)* key);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_session_ticket_send (gnutls_session_t session, uint nr, uint flags);

    int gnutls_srtp_set_profile (gnutls_session_t session, gnutls_srtp_profile_t profile);
    int gnutls_srtp_set_profile_direct (gnutls_session_t session, const(char)* profiles, const(char*)* err_pos);
    int gnutls_srtp_get_selected_profile (gnutls_session_t session, gnutls_srtp_profile_t* profile);
    const(char)* gnutls_srtp_get_profile_name (gnutls_srtp_profile_t profile);
    int gnutls_srtp_get_profile_id (const(char)* name, gnutls_srtp_profile_t* profile);
    int gnutls_srtp_get_keys (gnutls_session_t session, void* key_material, uint key_material_size, gnutls_datum_t* client_key, gnutls_datum_t* client_salt, gnutls_datum_t* server_key, gnutls_datum_t* server_salt);
    int gnutls_srtp_set_mki (gnutls_session_t session, const(gnutls_datum_t)* mki);
    int gnutls_srtp_get_mki (gnutls_session_t session, gnutls_datum_t* mki);
    int gnutls_alpn_get_selected_protocol (gnutls_session_t session, gnutls_datum_t* protocol);
    int gnutls_alpn_set_protocols (gnutls_session_t session, const(gnutls_datum_t)* protocols, uint protocols_size, uint flags);
    int gnutls_key_generate (gnutls_datum_t* key, uint key_size);
    int gnutls_priority_init (gnutls_priority_t* priority_cache, const(char)* priorities, const(char*)* err_pos);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_priority_init2 (gnutls_priority_t* priority_cache, const(char)* priorities, const(char*)* err_pos, uint flags);

    void gnutls_priority_deinit (gnutls_priority_t priority_cache);
    int gnutls_priority_get_cipher_suite_index (gnutls_priority_t pcache, uint idx, uint* sidx);
    const(char)* gnutls_priority_string_list (uint iter, uint flags);
    int gnutls_priority_set (gnutls_session_t session, gnutls_priority_t priority);
    int gnutls_priority_set_direct (gnutls_session_t session, const(char)* priorities, const(char*)* err_pos);
    int gnutls_priority_certificate_type_list (gnutls_priority_t pcache, const(uint*)* list);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
        int gnutls_priority_certificate_type_list2 (gnutls_priority_t pcache, const(uint*)* list, gnutls_ctype_target_t target);

    int gnutls_priority_sign_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_protocol_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_ecc_curve_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_group_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_kx_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_cipher_list (gnutls_priority_t pcache, const(uint*)* list);
    int gnutls_priority_mac_list (gnutls_priority_t pcache, const(uint*)* list);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
        const(char)* gnutls_get_system_config_file ();

    int gnutls_set_default_priority (gnutls_session_t session);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_set_default_priority_append (gnutls_session_t session, const(char)* add_prio, const(char*)* err_pos, uint flags);

    const(char)* gnutls_cipher_suite_get_name (gnutls_kx_algorithm_t kx_algorithm, gnutls_cipher_algorithm_t cipher_algorithm, gnutls_mac_algorithm_t mac_algorithm);
    gnutls_protocol_t gnutls_protocol_get_version (gnutls_session_t session);
    const(char)* gnutls_protocol_get_name (gnutls_protocol_t version_);
    int gnutls_session_set_data (gnutls_session_t session, const(void)* session_data, size_t session_data_size);
    int gnutls_session_get_data (gnutls_session_t session, void* session_data, size_t* session_data_size);
    int gnutls_session_get_data2 (gnutls_session_t session, gnutls_datum_t* data);
    void gnutls_session_get_random (gnutls_session_t session, gnutls_datum_t* client, gnutls_datum_t* server);
    void gnutls_session_get_master_secret (gnutls_session_t session, gnutls_datum_t* secret);
    char* gnutls_session_get_desc (gnutls_session_t session);
    void gnutls_session_set_verify_function (gnutls_session_t session, int function () func);
    void gnutls_session_set_verify_cert (gnutls_session_t session, const(char)* hostname, uint flags);
    void gnutls_session_set_verify_cert2 (gnutls_session_t session, gnutls_typed_vdata_st* data, uint elements, uint flags);
    uint gnutls_session_get_verify_cert_status (gnutls_session_t);
    int gnutls_session_set_premaster (gnutls_session_t session, uint entity, gnutls_protocol_t version_, gnutls_kx_algorithm_t kx, gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac, gnutls_compression_method_t comp, const(gnutls_datum_t)* master, const(gnutls_datum_t)* session_id);
    int gnutls_session_get_id (gnutls_session_t session, void* session_id, size_t* session_id_size);
    int gnutls_session_get_id2 (gnutls_session_t session, gnutls_datum_t* session_id);
    int gnutls_session_set_id (gnutls_session_t session, const(gnutls_datum_t)* sid);
    int gnutls_session_channel_binding (gnutls_session_t session, gnutls_channel_binding_t cbtype, gnutls_datum_t* cb);
    int gnutls_session_is_resumed (gnutls_session_t session);
    int gnutls_session_resumption_requested (gnutls_session_t session);
    void gnutls_db_set_cache_expiration (gnutls_session_t session, int seconds);
    uint gnutls_db_get_default_cache_expiration ();
    void gnutls_db_remove_session (gnutls_session_t session);
    void gnutls_db_set_retrieve_function (gnutls_session_t session, gnutls_db_retr_func retr_func);
    void gnutls_db_set_remove_function (gnutls_session_t session, gnutls_db_remove_func rem_func);
    void gnutls_db_set_store_function (gnutls_session_t session, gnutls_db_store_func store_func);
    void gnutls_db_set_ptr (gnutls_session_t session, void* ptr);
    void* gnutls_db_get_ptr (gnutls_session_t session);
    int gnutls_db_check_entry (gnutls_session_t session, gnutls_datum_t session_entry);
    time_t gnutls_db_check_entry_time (gnutls_datum_t* entry);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        time_t gnutls_db_check_entry_expire_time (gnutls_datum_t* entry);

    void gnutls_handshake_set_hook_function (gnutls_session_t session, uint htype, int when, gnutls_handshake_hook_func func);
    void gnutls_handshake_set_post_client_hello_function (gnutls_session_t session, gnutls_handshake_simple_hook_func func);
    void gnutls_handshake_set_max_packet_length (gnutls_session_t session, size_t max);
    const(char)* gnutls_check_version (const(char)* req_version);
    void gnutls_credentials_clear (gnutls_session_t session);
    int gnutls_credentials_set (gnutls_session_t session, gnutls_credentials_type_t type, void* cred);
    int gnutls_credentials_get (gnutls_session_t session, gnutls_credentials_type_t type, void** cred);
    void gnutls_anon_free_server_credentials (gnutls_anon_server_credentials_t sc);
    int gnutls_anon_allocate_server_credentials (gnutls_anon_server_credentials_t* sc);
    void gnutls_anon_set_server_dh_params (gnutls_anon_server_credentials_t res, gnutls_dh_params_t dh_params);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
        int gnutls_anon_set_server_known_dh_params (gnutls_anon_server_credentials_t res, gnutls_sec_param_t sec_param);

    void gnutls_anon_set_server_params_function (gnutls_anon_server_credentials_t res, int function () func);
    void gnutls_anon_free_client_credentials (gnutls_anon_client_credentials_t sc);
    int gnutls_anon_allocate_client_credentials (gnutls_anon_client_credentials_t* sc);
    void gnutls_certificate_free_credentials (gnutls_certificate_credentials_t sc);
    int gnutls_certificate_allocate_credentials (gnutls_certificate_credentials_t* res);
    int gnutls_certificate_get_issuer (gnutls_certificate_credentials_t sc, gnutls_x509_crt_t cert, gnutls_x509_crt_t* issuer, uint flags);
    int gnutls_certificate_get_crt_raw (gnutls_certificate_credentials_t sc, uint idx1, uint idx2, gnutls_datum_t* cert);
    void gnutls_certificate_free_keys (gnutls_certificate_credentials_t sc);
    void gnutls_certificate_free_cas (gnutls_certificate_credentials_t sc);
    void gnutls_certificate_free_ca_names (gnutls_certificate_credentials_t sc);
    void gnutls_certificate_free_crls (gnutls_certificate_credentials_t sc);
    void gnutls_certificate_set_dh_params (gnutls_certificate_credentials_t res, gnutls_dh_params_t dh_params);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
        int gnutls_certificate_set_known_dh_params (gnutls_certificate_credentials_t res, gnutls_sec_param_t sec_param);

    void gnutls_certificate_set_verify_flags (gnutls_certificate_credentials_t res, uint flags);
    uint gnutls_certificate_get_verify_flags (gnutls_certificate_credentials_t res);
    void gnutls_certificate_set_flags (gnutls_certificate_credentials_t, uint flags);
    void gnutls_certificate_set_verify_limits (gnutls_certificate_credentials_t res, uint max_bits, uint max_depth);
    int gnutls_certificate_set_x509_system_trust (gnutls_certificate_credentials_t cred);
    int gnutls_certificate_set_x509_trust_file (gnutls_certificate_credentials_t cred, const(char)* cafile, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_trust_dir (gnutls_certificate_credentials_t cred, const(char)* ca_dir, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_trust_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* ca, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_crl_file (gnutls_certificate_credentials_t res, const(char)* crlfile, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_crl_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* CRL, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_key_file (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_key_file2 (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, gnutls_x509_crt_fmt_t type, const(char)* pass, uint flags);
    int gnutls_certificate_set_x509_key_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, gnutls_x509_crt_fmt_t type);
    int gnutls_certificate_set_x509_key_mem2 (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, gnutls_x509_crt_fmt_t type, const(char)* pass, uint flags);
    void gnutls_certificate_send_x509_rdn_sequence (gnutls_session_t session, int status);
    int gnutls_certificate_set_x509_simple_pkcs12_file (gnutls_certificate_credentials_t res, const(char)* pkcs12file, gnutls_x509_crt_fmt_t type, const(char)* password);
    int gnutls_certificate_set_x509_simple_pkcs12_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* p12blob, gnutls_x509_crt_fmt_t type, const(char)* password);
    int gnutls_certificate_set_x509_key (gnutls_certificate_credentials_t res, gnutls_x509_crt_t* cert_list, int cert_list_size, gnutls_x509_privkey_t key);
    int gnutls_certificate_set_x509_trust (gnutls_certificate_credentials_t res, gnutls_x509_crt_t* ca_list, int ca_list_size);
    int gnutls_certificate_set_x509_crl (gnutls_certificate_credentials_t res, gnutls_x509_crl_t* crl_list, int crl_list_size);
    int gnutls_certificate_get_x509_key (gnutls_certificate_credentials_t res, uint index, gnutls_x509_privkey_t* key);
    int gnutls_certificate_get_x509_crt (gnutls_certificate_credentials_t res, uint index, gnutls_x509_crt_t** crt_list, uint* crt_list_size);
    void gnutls_certificate_set_ocsp_status_request_function (gnutls_certificate_credentials_t res, gnutls_status_request_ocsp_func ocsp_func, void* ptr);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
        int gnutls_certificate_set_ocsp_status_request_function2 (gnutls_certificate_credentials_t res, uint idx, gnutls_status_request_ocsp_func ocsp_func, void* ptr);

    int gnutls_certificate_set_ocsp_status_request_file (gnutls_certificate_credentials_t res, const(char)* response_file, uint idx);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
    {
        int gnutls_certificate_set_ocsp_status_request_file2 (gnutls_certificate_credentials_t res, const(char)* response_file, uint idx, gnutls_x509_crt_fmt_t fmt);
        int gnutls_certificate_set_ocsp_status_request_mem (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* resp, uint idx, gnutls_x509_crt_fmt_t fmt);
        time_t gnutls_certificate_get_ocsp_expiration (gnutls_certificate_credentials_t sc, uint idx, int oidx, uint flags);
    }

    int gnutls_ocsp_status_request_enable_client (gnutls_session_t session, gnutls_datum_t* responder_id, size_t responder_id_size, gnutls_datum_t* request_extensions);
    int gnutls_ocsp_status_request_get (gnutls_session_t session, gnutls_datum_t* response);
    uint gnutls_ocsp_status_request_is_checked (gnutls_session_t session, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_ocsp_status_request_get2 (gnutls_session_t session, uint idx, gnutls_datum_t* response);

    int gnutls_certificate_set_rawpk_key_mem (gnutls_certificate_credentials_t cred, const(gnutls_datum_t)* spki, const(gnutls_datum_t)* pkey, gnutls_x509_crt_fmt_t format, const(char)* pass, uint key_usage, const(char*)* names, uint names_length, uint flags);
    int gnutls_certificate_set_rawpk_key_file (gnutls_certificate_credentials_t cred, const(char)* rawpkfile, const(char)* privkeyfile, gnutls_x509_crt_fmt_t format, const(char)* pass, uint key_usage, const(char*)* names, uint names_length, uint privkey_flags, uint pkcs11_flags);
    int gnutls_global_init ();
    void gnutls_global_deinit ();
    void gnutls_global_set_mutex (mutex_init_func init, mutex_deinit_func deinit, mutex_lock_func lock, mutex_unlock_func unlock);
    void gnutls_global_set_time_function (gnutls_time_func time_func);
    void gnutls_memset (void* data, int c, size_t size);
    int gnutls_memcmp (const(void)* s1, const(void)* s2, size_t n);
    void gnutls_global_set_log_function (gnutls_log_func log_func);
    void gnutls_global_set_audit_log_function (gnutls_audit_log_func log_func);
    void gnutls_global_set_log_level (int level);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
    {
        gnutls_keylog_func gnutls_session_get_keylog_function (const gnutls_session_t session);
        void gnutls_session_set_keylog_function (gnutls_session_t session, gnutls_keylog_func func);
    }

    int gnutls_dh_params_init (gnutls_dh_params_t* dh_params);
    void gnutls_dh_params_deinit (gnutls_dh_params_t dh_params);
    int gnutls_dh_params_import_raw (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* generator);
    int gnutls_dh_params_import_dsa (gnutls_dh_params_t dh_params, gnutls_x509_privkey_t key);
    int gnutls_dh_params_import_raw2 (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* generator, uint key_bits);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
        int gnutls_dh_params_import_raw3 (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* q, const(gnutls_datum_t)* generator);

    int gnutls_dh_params_import_pkcs3 (gnutls_dh_params_t params, const(gnutls_datum_t)* pkcs3_params, gnutls_x509_crt_fmt_t format);
    int gnutls_dh_params_generate2 (gnutls_dh_params_t params, uint bits);
    int gnutls_dh_params_export_pkcs3 (gnutls_dh_params_t params, gnutls_x509_crt_fmt_t format, ubyte* params_data, size_t* params_data_size);
    int gnutls_dh_params_export2_pkcs3 (gnutls_dh_params_t params, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
    int gnutls_dh_params_export_raw (gnutls_dh_params_t params, gnutls_datum_t* prime, gnutls_datum_t* generator, uint* bits);
    int gnutls_dh_params_cpy (gnutls_dh_params_t dst, gnutls_dh_params_t src);
    int gnutls_system_recv_timeout (gnutls_transport_ptr_t ptr, uint ms);
    void gnutls_transport_set_int2 (gnutls_session_t session, int r, int s);
    void gnutls_transport_get_int2 (gnutls_session_t session, int* r, int* s);
    int gnutls_transport_get_int (gnutls_session_t session);
    void gnutls_transport_set_ptr (gnutls_session_t session, gnutls_transport_ptr_t ptr);
    void gnutls_transport_set_ptr2 (gnutls_session_t session, gnutls_transport_ptr_t recv_ptr, gnutls_transport_ptr_t send_ptr);
    gnutls_transport_ptr_t gnutls_transport_get_ptr (gnutls_session_t session);
    void gnutls_transport_get_ptr2 (gnutls_session_t session, gnutls_transport_ptr_t* recv_ptr, gnutls_transport_ptr_t* send_ptr);
    void gnutls_transport_set_vec_push_function (gnutls_session_t session, gnutls_vec_push_func vec_func);
    void gnutls_transport_set_push_function (gnutls_session_t session, gnutls_push_func push_func);
    void gnutls_transport_set_pull_function (gnutls_session_t session, gnutls_pull_func pull_func);
    void gnutls_transport_set_pull_timeout_function (gnutls_session_t session, gnutls_pull_timeout_func func);
    void gnutls_transport_set_errno_function (gnutls_session_t session, gnutls_errno_func errno_func);
    void gnutls_transport_set_errno (gnutls_session_t session, int err);
    void gnutls_session_set_ptr (gnutls_session_t session, void* ptr);
    void* gnutls_session_get_ptr (gnutls_session_t session);
    void gnutls_openpgp_send_cert (gnutls_session_t session, gnutls_openpgp_crt_status_t status);
    int gnutls_fingerprint (gnutls_digest_algorithm_t algo, const(gnutls_datum_t)* data, void* result, size_t* result_size);
    int gnutls_random_art (gnutls_random_art_t type, const(char)* key_type, uint key_size, void* fpr, size_t fpr_size, gnutls_datum_t* art);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_9)
    {
        int gnutls_idna_map (const(char)* input, uint ilen, gnutls_datum_t* out_, uint flags);
        int gnutls_idna_reverse_map (const(char)* input, uint ilen, gnutls_datum_t* out_, uint flags);
    }

    void gnutls_srp_free_client_credentials (gnutls_srp_client_credentials_t sc);
    int gnutls_srp_allocate_client_credentials (gnutls_srp_client_credentials_t* sc);
    int gnutls_srp_set_client_credentials (gnutls_srp_client_credentials_t res, const(char)* username, const(char)* password);
    void gnutls_srp_free_server_credentials (gnutls_srp_server_credentials_t sc);
    int gnutls_srp_allocate_server_credentials (gnutls_srp_server_credentials_t* sc);
    int gnutls_srp_set_server_credentials_file (gnutls_srp_server_credentials_t res, const(char)* password_file, const(char)* password_conf_file);
    const(char)* gnutls_srp_server_get_username (gnutls_session_t session);
    void gnutls_srp_set_prime_bits (gnutls_session_t session, uint bits);
    int gnutls_srp_verifier (const(char)* username, const(char)* password, const(gnutls_datum_t)* salt, const(gnutls_datum_t)* generator, const(gnutls_datum_t)* prime, gnutls_datum_t* res);
    void gnutls_srp_set_server_credentials_function (gnutls_srp_server_credentials_t cred, int function () func);
    void gnutls_srp_set_client_credentials_function (gnutls_srp_client_credentials_t cred, int function () func);
    int gnutls_srp_base64_encode (const(gnutls_datum_t)* data, char* result, size_t* result_size);
    int gnutls_srp_base64_encode2 (const(gnutls_datum_t)* data, gnutls_datum_t* result);
    int gnutls_srp_base64_decode (const(gnutls_datum_t)* b64_data, char* result, size_t* result_size);
    int gnutls_srp_base64_decode2 (const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);
    void gnutls_srp_set_server_fake_salt_seed (gnutls_srp_server_credentials_t sc, const(gnutls_datum_t)* seed, uint salt_length);
    void gnutls_psk_free_client_credentials (gnutls_psk_client_credentials_t sc);
    int gnutls_psk_allocate_client_credentials (gnutls_psk_client_credentials_t* sc);
    int gnutls_psk_set_client_credentials (gnutls_psk_client_credentials_t res, const(char)* username, const(gnutls_datum_t)* key, gnutls_psk_key_flags flags);
    void gnutls_psk_free_server_credentials (gnutls_psk_server_credentials_t sc);
    int gnutls_psk_allocate_server_credentials (gnutls_psk_server_credentials_t* sc);
    int gnutls_psk_set_server_credentials_file (gnutls_psk_server_credentials_t res, const(char)* password_file);
    int gnutls_psk_set_server_credentials_hint (gnutls_psk_server_credentials_t res, const(char)* hint);
    const(char)* gnutls_psk_server_get_username (gnutls_session_t session);
    const(char)* gnutls_psk_client_get_hint (gnutls_session_t session);
    void gnutls_psk_set_server_credentials_function (gnutls_psk_server_credentials_t cred, int function () func);
    void gnutls_psk_set_client_credentials_function (gnutls_psk_client_credentials_t cred, int function () func);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
    {
        int gnutls_psk_set_client_credentials2 (gnutls_psk_client_credentials_t res, const(gnutls_datum_t)* username, const(gnutls_datum_t)* key, gnutls_psk_key_flags flags);
        int gnutls_psk_server_get_username2 (gnutls_session_t session, gnutls_datum_t* out_);
        void gnutls_psk_set_server_credentials_function2 (gnutls_psk_server_credentials_t cred, int function () func);
        void gnutls_psk_set_client_credentials_function2 (gnutls_psk_client_credentials_t cred, int function () func);
    }

    int gnutls_hex_encode (const(gnutls_datum_t)* data, char* result, size_t* result_size);
    int gnutls_hex_decode (const(gnutls_datum_t)* hex_data, void* result, size_t* result_size);
    int gnutls_hex_encode2 (const(gnutls_datum_t)* data, gnutls_datum_t* result);
    int gnutls_hex_decode2 (const(gnutls_datum_t)* data, gnutls_datum_t* result);
    void gnutls_psk_set_server_dh_params (gnutls_psk_server_credentials_t res, gnutls_dh_params_t dh_params);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
        int gnutls_psk_set_server_known_dh_params (gnutls_psk_server_credentials_t res, gnutls_sec_param_t sec_param);

    void gnutls_psk_set_server_params_function (gnutls_psk_server_credentials_t res, int function () func);
    gnutls_credentials_type_t gnutls_auth_get_type (gnutls_session_t session);
    gnutls_credentials_type_t gnutls_auth_server_get_type (gnutls_session_t session);
    gnutls_credentials_type_t gnutls_auth_client_get_type (gnutls_session_t session);
    void gnutls_dh_set_prime_bits (gnutls_session_t session, uint bits);
    int gnutls_dh_get_secret_bits (gnutls_session_t session);
    int gnutls_dh_get_peers_public_bits (gnutls_session_t session);
    int gnutls_dh_get_prime_bits (gnutls_session_t session);
    int gnutls_dh_get_group (gnutls_session_t session, gnutls_datum_t* raw_gen, gnutls_datum_t* raw_prime);
    int gnutls_dh_get_pubkey (gnutls_session_t session, gnutls_datum_t* raw_key);
    void gnutls_certificate_set_retrieve_function (gnutls_certificate_credentials_t cred, int function () func);
    void gnutls_certificate_set_verify_function (gnutls_certificate_credentials_t cred, int function () func);
    void gnutls_certificate_server_set_request (gnutls_session_t session, gnutls_certificate_request_t req);
    const(gnutls_datum_t)* gnutls_certificate_get_peers (gnutls_session_t session, uint* list_size);
    const(gnutls_datum_t)* gnutls_certificate_get_ours (gnutls_session_t session);
    int gnutls_certificate_get_peers_subkey_id (gnutls_session_t session, gnutls_datum_t* id);
    time_t gnutls_certificate_activation_time_peers (gnutls_session_t session);
    time_t gnutls_certificate_expiration_time_peers (gnutls_session_t session);
    uint gnutls_certificate_client_get_request_status (gnutls_session_t session);
    int gnutls_certificate_verify_peers2 (gnutls_session_t session, uint* status);
    int gnutls_certificate_verify_peers3 (gnutls_session_t session, const(char)* hostname, uint* status);
    int gnutls_certificate_verify_peers (gnutls_session_t session, gnutls_typed_vdata_st* data, uint elements, uint* status);
    int gnutls_certificate_verification_status_print (uint status, gnutls_certificate_type_t type, gnutls_datum_t* out_, uint flags);
    int gnutls_pem_base64_encode (const(char)* msg, const(gnutls_datum_t)* data, char* result, size_t* result_size);
    int gnutls_pem_base64_decode (const(char)* header, const(gnutls_datum_t)* b64_data, ubyte* result, size_t* result_size);
    int gnutls_pem_base64_encode2 (const(char)* msg, const(gnutls_datum_t)* data, gnutls_datum_t* result);
    int gnutls_pem_base64_decode2 (const(char)* header, const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_base64_encode2 (const(gnutls_datum_t)* data, gnutls_datum_t* result);
        int gnutls_base64_decode2 (const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);
    }

    void gnutls_certificate_set_params_function (gnutls_certificate_credentials_t res, int function () func);
    void gnutls_anon_set_params_function (gnutls_anon_server_credentials_t res, int function () func);
    void gnutls_psk_set_params_function (gnutls_psk_server_credentials_t res, int function () func);
    int gnutls_hex2bin (const(char)* hex_data, size_t hex_size, void* bin_data, size_t* bin_size);
    int gnutls_tdb_init (gnutls_tdb_t* tdb);
    void gnutls_tdb_set_store_func (gnutls_tdb_t tdb, gnutls_tdb_store_func store);
    void gnutls_tdb_set_store_commitment_func (gnutls_tdb_t tdb, gnutls_tdb_store_commitment_func cstore);
    void gnutls_tdb_set_verify_func (gnutls_tdb_t tdb, gnutls_tdb_verify_func verify);
    void gnutls_tdb_deinit (gnutls_tdb_t tdb);
    int gnutls_verify_stored_pubkey (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_certificate_type_t cert_type, const(gnutls_datum_t)* cert, uint flags);
    int gnutls_store_commitment (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_digest_algorithm_t hash_algo, const(gnutls_datum_t)* hash, time_t expiration, uint flags);
    int gnutls_store_pubkey (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_certificate_type_t cert_type, const(gnutls_datum_t)* cert, time_t expiration, uint flags);
    int gnutls_load_file (const(char)* filename, gnutls_datum_t* data);
    uint gnutls_url_is_supported (const(char)* url);
    void gnutls_certificate_set_pin_function (gnutls_certificate_credentials_t, gnutls_pin_callback_t fn, void* userdata);
    int gnutls_buffer_append_data (gnutls_buffer_t, const(void)* data, size_t data_size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
        int gnutls_utf8_password_normalize (const(ubyte)* password, uint password_len, gnutls_datum_t* out_, uint flags);

    void gnutls_ext_set_data (gnutls_session_t session, uint type, gnutls_ext_priv_data_t);
    int gnutls_ext_get_data (gnutls_session_t session, uint type, gnutls_ext_priv_data_t*);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
    {
        uint gnutls_ext_get_current_msg (gnutls_session_t session);
        int gnutls_ext_raw_parse (void* ctx, gnutls_ext_raw_process_func cb, const(gnutls_datum_t)* data, uint flags);
    }

    int gnutls_ext_register (const(char)* name, int type, gnutls_ext_parse_type_t parse_point, gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func, gnutls_ext_unpack_func unpack_func);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
        int gnutls_session_ext_register (gnutls_session_t, const(char)* name, int type, gnutls_ext_parse_type_t parse_point, gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func, gnutls_ext_unpack_func unpack_func, uint flags);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
        const(char)* gnutls_ext_get_name (uint ext);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_14)
        const(char)* gnutls_ext_get_name2 (gnutls_session_t session, uint tls_id, gnutls_ext_parse_type_t parse_point);

    int gnutls_supplemental_register (const(char)* name, gnutls_supplemental_data_format_type_t type, gnutls_supp_recv_func supp_recv_func, gnutls_supp_send_func supp_send_func);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
        int gnutls_session_supplemental_register (gnutls_session_t session, const(char)* name, gnutls_supplemental_data_format_type_t type, gnutls_supp_recv_func supp_recv_func, gnutls_supp_send_func supp_send_func, uint flags);

    void gnutls_supplemental_recv (gnutls_session_t session, uint do_recv_supplemental);
    void gnutls_supplemental_send (gnutls_session_t session, uint do_send_supplemental);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
    {
        int gnutls_anti_replay_init (gnutls_anti_replay_t* anti_replay);
        void gnutls_anti_replay_deinit (gnutls_anti_replay_t anti_replay);
        void gnutls_anti_replay_set_window (gnutls_anti_replay_t anti_replay, uint window);
        void gnutls_anti_replay_enable (gnutls_session_t session, gnutls_anti_replay_t anti_replay);
        void gnutls_anti_replay_set_add_function (gnutls_anti_replay_t, gnutls_db_add_func add_func);
    }

    void gnutls_anti_replay_set_ptr (gnutls_anti_replay_t, void* ptr);
    uint gnutls_fips140_mode_enabled ();

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        void gnutls_fips140_set_mode (gnutls_fips_mode_t mode, uint flags);
}
else
{
    // external global symbols
    mixin externField!(gnutls_alloc_function,  "gnutls_malloc");
    mixin externField!(gnutls_realloc_function,  "gnutls_realloc");
    mixin externField!(gnutls_calloc_function,  "gnutls_calloc");
    mixin externField!(gnutls_free_function,  "gnutls_free");
    mixin externField!(char* function (const(char)*), "gnutls_strdup");

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_2)
    {
        mixin externField!(const gnutls_datum_t, "gnutls_srp_8192_group_prime");
        mixin externField!(const gnutls_datum_t, "gnutls_srp_8192_group_generator");
    }

    mixin externField!(const gnutls_datum_t, "gnutls_srp_4096_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_4096_group_generator");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_3072_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_3072_group_generator");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_2048_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_2048_group_generator");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_1536_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_1536_group_generator");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_1024_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_srp_1024_group_generator");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_8192_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_8192_group_generator");
    mixin externField!(const uint, "gnutls_ffdhe_8192_key_bits");

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
    {
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_6144_group_prime");
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_6144_group_generator");
        mixin externField!(const uint, "gnutls_ffdhe_6144_key_bits");
    }

    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_4096_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_4096_group_generator");
    mixin externField!(const uint, "gnutls_ffdhe_4096_key_bits");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_3072_group_prime");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_3072_group_generator");
    mixin externField!(const uint, "gnutls_ffdhe_3072_key_bits");
    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_2048_group_prime");

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
    {
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_2048_group_q");
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_3072_group_q");
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_4096_group_q");
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_6144_group_q");
        mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_8192_group_q");
    }

    mixin externField!(const gnutls_datum_t, "gnutls_ffdhe_2048_group_generator");
    mixin externField!(const uint, "gnutls_ffdhe_2048_key_bits");

    // functions
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_pk_algorithm_get_name = const(char)* function (gnutls_pk_algorithm_t algorithm);
        alias pgnutls_init = int function (gnutls_session_t* session, uint flags);
        alias pgnutls_deinit = void function (gnutls_session_t session);
        alias pgnutls_bye = int function (gnutls_session_t session, gnutls_close_request_t how);
        alias pgnutls_handshake = int function (gnutls_session_t session);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_reauth = int function (gnutls_session_t session, uint flags);

        alias pgnutls_handshake_set_timeout = void function (gnutls_session_t session, uint ms);
        alias pgnutls_rehandshake = int function (gnutls_session_t session);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_session_key_update = int function (gnutls_session_t session, uint flags);

        alias pgnutls_alert_get = gnutls_alert_description_t function (gnutls_session_t session);
        alias pgnutls_alert_send = int function (gnutls_session_t session, gnutls_alert_level_t level, gnutls_alert_description_t desc);
        alias pgnutls_alert_send_appropriate = int function (gnutls_session_t session, int err);
        alias pgnutls_alert_get_name = const(char)* function (gnutls_alert_description_t alert);
        alias pgnutls_alert_get_strname = const(char)* function (gnutls_alert_description_t alert);
        alias pgnutls_pk_bits_to_sec_param = gnutls_sec_param_t function (gnutls_pk_algorithm_t algo, uint bits);
        alias pgnutls_sec_param_get_name = const(char)* function (gnutls_sec_param_t param);
        alias pgnutls_sec_param_to_pk_bits = uint function (gnutls_pk_algorithm_t algo, gnutls_sec_param_t param);
        alias pgnutls_sec_param_to_symmetric_bits = uint function (gnutls_sec_param_t param);
        alias pgnutls_ecc_curve_get_name = const(char)* function (gnutls_ecc_curve_t curve);
        alias pgnutls_ecc_curve_get_oid = const(char)* function (gnutls_ecc_curve_t curve);
        alias pgnutls_group_get_name = const(char)* function (gnutls_group_t group);
        alias pgnutls_ecc_curve_get_size = int function (gnutls_ecc_curve_t curve);
        alias pgnutls_ecc_curve_get = gnutls_ecc_curve_t function (gnutls_session_t session);
        alias pgnutls_group_get = gnutls_group_t function (gnutls_session_t session);
        alias pgnutls_cipher_get = gnutls_cipher_algorithm_t function (gnutls_session_t session);
        alias pgnutls_kx_get = gnutls_kx_algorithm_t function (gnutls_session_t session);
        alias pgnutls_mac_get = gnutls_mac_algorithm_t function (gnutls_session_t session);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
            alias pgnutls_prf_hash_get = gnutls_digest_algorithm_t function (const gnutls_session_t session);

        alias pgnutls_certificate_type_get = gnutls_certificate_type_t function (gnutls_session_t session);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            alias pgnutls_certificate_type_get2 = gnutls_certificate_type_t function (gnutls_session_t session, gnutls_ctype_target_t target);

        alias pgnutls_sign_algorithm_get = int function (gnutls_session_t session);
        alias pgnutls_sign_algorithm_get_client = int function (gnutls_session_t session);
        alias pgnutls_sign_algorithm_get_requested = int function (gnutls_session_t session, size_t indx, gnutls_sign_algorithm_t* algo);
        alias pgnutls_cipher_get_name = const(char)* function (gnutls_cipher_algorithm_t algorithm);
        alias pgnutls_mac_get_name = const(char)* function (gnutls_mac_algorithm_t algorithm);
        alias pgnutls_digest_get_name = const(char)* function (gnutls_digest_algorithm_t algorithm);
        alias pgnutls_digest_get_oid = const(char)* function (gnutls_digest_algorithm_t algorithm);
        alias pgnutls_kx_get_name = const(char)* function (gnutls_kx_algorithm_t algorithm);
        alias pgnutls_certificate_type_get_name = const(char)* function (gnutls_certificate_type_t type);
        alias pgnutls_pk_get_name = const(char)* function (gnutls_pk_algorithm_t algorithm);
        alias pgnutls_pk_get_oid = const(char)* function (gnutls_pk_algorithm_t algorithm);
        alias pgnutls_sign_get_name = const(char)* function (gnutls_sign_algorithm_t algorithm);
        alias pgnutls_sign_get_oid = const(char)* function (gnutls_sign_algorithm_t sign);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            alias pgnutls_gost_paramset_get_name = const(char)* function (gnutls_gost_paramset_t param);
            alias pgnutls_gost_paramset_get_oid = const(char)* function (gnutls_gost_paramset_t param);
        }

        alias pgnutls_cipher_get_key_size = size_t function (gnutls_cipher_algorithm_t algorithm);
        alias pgnutls_mac_get_key_size = size_t function (gnutls_mac_algorithm_t algorithm);
        alias pgnutls_sign_is_secure = uint function (gnutls_sign_algorithm_t algorithm);
        alias pgnutls_sign_is_secure2 = uint function (gnutls_sign_algorithm_t algorithm, uint flags);
        alias pgnutls_sign_get_hash_algorithm = gnutls_digest_algorithm_t function (gnutls_sign_algorithm_t sign);
        alias pgnutls_sign_get_pk_algorithm = gnutls_pk_algorithm_t function (gnutls_sign_algorithm_t sign);
        alias pgnutls_pk_to_sign = gnutls_sign_algorithm_t function (gnutls_pk_algorithm_t pk, gnutls_digest_algorithm_t hash);
        alias pgnutls_sign_supports_pk_algorithm = uint function (gnutls_sign_algorithm_t sign, gnutls_pk_algorithm_t pk);
        alias pgnutls_mac_get_id = gnutls_mac_algorithm_t function (const(char)* name);
        alias pgnutls_digest_get_id = gnutls_digest_algorithm_t function (const(char)* name);
        alias pgnutls_cipher_get_id = gnutls_cipher_algorithm_t function (const(char)* name);
        alias pgnutls_kx_get_id = gnutls_kx_algorithm_t function (const(char)* name);
        alias pgnutls_protocol_get_id = gnutls_protocol_t function (const(char)* name);
        alias pgnutls_certificate_type_get_id = gnutls_certificate_type_t function (const(char)* name);
        alias pgnutls_pk_get_id = gnutls_pk_algorithm_t function (const(char)* name);
        alias pgnutls_sign_get_id = gnutls_sign_algorithm_t function (const(char)* name);
        alias pgnutls_ecc_curve_get_id = gnutls_ecc_curve_t function (const(char)* name);
        alias pgnutls_ecc_curve_get_pk = gnutls_pk_algorithm_t function (gnutls_ecc_curve_t curve);
        alias pgnutls_group_get_id = gnutls_group_t function (const(char)* name);
        alias pgnutls_oid_to_digest = gnutls_digest_algorithm_t function (const(char)* oid);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            alias pgnutls_oid_to_mac = gnutls_mac_algorithm_t function (const(char)* oid);

        alias pgnutls_oid_to_pk = gnutls_pk_algorithm_t function (const(char)* oid);
        alias pgnutls_oid_to_sign = gnutls_sign_algorithm_t function (const(char)* oid);
        alias pgnutls_oid_to_ecc_curve = gnutls_ecc_curve_t function (const(char)* oid);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_oid_to_gost_paramset = gnutls_gost_paramset_t function (const(char)* oid);

        alias pgnutls_ecc_curve_list = const(gnutls_ecc_curve_t)* function ();
        alias pgnutls_group_list = const(gnutls_group_t)* function ();
        alias pgnutls_cipher_list = const(gnutls_cipher_algorithm_t)* function ();
        alias pgnutls_mac_list = const(gnutls_mac_algorithm_t)* function ();
        alias pgnutls_digest_list = const(gnutls_digest_algorithm_t)* function ();
        alias pgnutls_protocol_list = const(gnutls_protocol_t)* function ();
        alias pgnutls_certificate_type_list = const(gnutls_certificate_type_t)* function ();
        alias pgnutls_kx_list = const(gnutls_kx_algorithm_t)* function ();
        alias pgnutls_pk_list = const(gnutls_pk_algorithm_t)* function ();
        alias pgnutls_sign_list = const(gnutls_sign_algorithm_t)* function ();
        alias pgnutls_cipher_suite_info = const(char)* function (size_t idx, ubyte* cs_id, gnutls_kx_algorithm_t* kx, gnutls_cipher_algorithm_t* cipher, gnutls_mac_algorithm_t* mac, gnutls_protocol_t* min_version);
        alias pgnutls_error_is_fatal = int function (int error);
        alias pgnutls_error_to_alert = int function (int err, int* level);
        alias pgnutls_perror = void function (int error);
        alias pgnutls_strerror = const(char)* function (int error);
        alias pgnutls_strerror_name = const(char)* function (int error);
        alias pgnutls_handshake_set_private_extensions = void function (gnutls_session_t session, int allow);
        alias pgnutls_handshake_set_random = int function (gnutls_session_t session, const(gnutls_datum_t)* random);
        alias pgnutls_handshake_get_last_out = gnutls_handshake_description_t function (gnutls_session_t session);
        alias pgnutls_handshake_get_last_in = gnutls_handshake_description_t function (gnutls_session_t session);
        alias pgnutls_heartbeat_ping = int function (gnutls_session_t session, size_t data_size, uint max_tries, uint flags);
        alias pgnutls_heartbeat_pong = int function (gnutls_session_t session, uint flags);
        alias pgnutls_record_set_timeout = void function (gnutls_session_t session, uint ms);
        alias pgnutls_record_disable_padding = void function (gnutls_session_t session);
        alias pgnutls_record_cork = void function (gnutls_session_t session);
        alias pgnutls_record_uncork = int function (gnutls_session_t session, uint flags);
        alias pgnutls_record_discard_queued = size_t function (gnutls_session_t session);
        alias pgnutls_record_get_state = int function (gnutls_session_t session, uint read, gnutls_datum_t* mac_key, gnutls_datum_t* IV, gnutls_datum_t* cipher_key, ref ubyte[8] seq_number);
        alias pgnutls_record_set_state = int function (gnutls_session_t session, uint read, ref const(ubyte)[8] seq_number);
        alias pgnutls_range_split = int function (gnutls_session_t session, const(gnutls_range_st)* orig, gnutls_range_st* small_range, gnutls_range_st* rem_range);
        alias pgnutls_record_send = ssize_t function (gnutls_session_t session, const(void)* data, size_t data_size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_record_send2 = ssize_t function (gnutls_session_t session, const(void)* data, size_t data_size, size_t pad, uint flags);

        alias pgnutls_record_send_range = ssize_t function (gnutls_session_t session, const(void)* data, size_t data_size, const(gnutls_range_st)* range);
        alias pgnutls_record_recv = ssize_t function (gnutls_session_t session, void* data, size_t data_size);
        alias pgnutls_record_recv_packet = ssize_t function (gnutls_session_t session, gnutls_packet_t* packet);
        alias pgnutls_packet_get = void function (gnutls_packet_t packet, gnutls_datum_t* data, ubyte* sequence);
        alias pgnutls_packet_deinit = void function (gnutls_packet_t packet);
        alias pgnutls_record_recv_seq = ssize_t function (gnutls_session_t session, void* data, size_t data_size, ubyte* seq);
        alias pgnutls_record_overhead_size = size_t function (gnutls_session_t session);
        alias pgnutls_est_record_overhead_size = size_t function (gnutls_protocol_t version_, gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac, gnutls_compression_method_t comp, uint flags);
        alias pgnutls_session_enable_compatibility_mode = void function (gnutls_session_t session);
        alias pgnutls_record_can_use_length_hiding = uint function (gnutls_session_t session);
        alias pgnutls_record_get_direction = int function (gnutls_session_t session);
        alias pgnutls_record_get_max_size = size_t function (gnutls_session_t session);
        alias pgnutls_record_set_max_size = ssize_t function (gnutls_session_t session, size_t size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            alias pgnutls_record_set_max_recv_size = ssize_t function (gnutls_session_t session, size_t size);

        alias pgnutls_record_check_pending = size_t function (gnutls_session_t session);
        alias pgnutls_record_check_corked = size_t function (gnutls_session_t session);


        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            alias pgnutls_record_set_max_early_data_size = int function (gnutls_session_t session, size_t size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            alias pgnutls_record_get_max_early_data_size = size_t function (gnutls_session_t session);
            alias pgnutls_record_send_early_data = ssize_t function (gnutls_session_t session, const(void)* data, size_t length);
            alias pgnutls_record_recv_early_data = ssize_t function (gnutls_session_t session, void* data, size_t data_size);
        }

        alias pgnutls_session_force_valid = void function (gnutls_session_t session);
        alias pgnutls_prf = int function (gnutls_session_t session, size_t label_size, const(char)* label, int server_random_first, size_t extra_size, const(char)* extra, size_t outsize, char* out_);
        alias pgnutls_prf_rfc5705 = int function (gnutls_session_t session, size_t label_size, const(char)* label, size_t context_size, const(char)* context, size_t outsize, char* out_);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            alias pgnutls_prf_early = int function (gnutls_session_t session, size_t label_size, const(char)* label, size_t context_size, const(char)* context, size_t outsize, char* out_);

        alias pgnutls_prf_raw = int function (gnutls_session_t session, size_t label_size, const(char)* label, size_t seed_size, const(char)* seed, size_t outsize, char* out_);
        alias pgnutls_server_name_set = int function (gnutls_session_t session, gnutls_server_name_type_t type, const(void)* name, size_t name_length);
        alias pgnutls_server_name_get = int function (gnutls_session_t session, void* data, size_t* data_length, uint* type, uint indx);
        alias pgnutls_heartbeat_get_timeout = uint function (gnutls_session_t session);
        alias pgnutls_heartbeat_set_timeouts = void function (gnutls_session_t session, uint retrans_timeout, uint total_timeout);
        alias pgnutls_heartbeat_enable = void function (gnutls_session_t session, uint type);
        alias pgnutls_heartbeat_allowed = uint function (gnutls_session_t session, uint type);
        alias pgnutls_safe_renegotiation_status = uint function (gnutls_session_t session);
        alias pgnutls_session_ext_master_secret_status = uint function (gnutls_session_t session);
        alias pgnutls_session_etm_status = uint function (gnutls_session_t session);
        alias pgnutls_session_get_flags = uint function (gnutls_session_t session);
        alias pgnutls_supplemental_get_name = const(char)* function (gnutls_supplemental_data_format_type_t type);
        alias pgnutls_session_ticket_key_generate = int function (gnutls_datum_t* key);
        alias pgnutls_session_ticket_enable_client = int function (gnutls_session_t session);
        alias pgnutls_session_ticket_enable_server = int function (gnutls_session_t session, const(gnutls_datum_t)* key);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_session_ticket_send = int function (gnutls_session_t session, uint nr, uint flags);

        alias pgnutls_srtp_set_profile = int function (gnutls_session_t session, gnutls_srtp_profile_t profile);
        alias pgnutls_srtp_set_profile_direct = int function (gnutls_session_t session, const(char)* profiles, const(char*)* err_pos);
        alias pgnutls_srtp_get_selected_profile = int function (gnutls_session_t session, gnutls_srtp_profile_t* profile);
        alias pgnutls_srtp_get_profile_name = const(char)* function (gnutls_srtp_profile_t profile);
        alias pgnutls_srtp_get_profile_id = int function (const(char)* name, gnutls_srtp_profile_t* profile);
        alias pgnutls_srtp_get_keys = int function (gnutls_session_t session, void* key_material, uint key_material_size, gnutls_datum_t* client_key, gnutls_datum_t* client_salt, gnutls_datum_t* server_key, gnutls_datum_t* server_salt);
        alias pgnutls_srtp_set_mki = int function (gnutls_session_t session, const(gnutls_datum_t)* mki);
        alias pgnutls_srtp_get_mki = int function (gnutls_session_t session, gnutls_datum_t* mki);
        alias pgnutls_alpn_get_selected_protocol = int function (gnutls_session_t session, gnutls_datum_t* protocol);
        alias pgnutls_alpn_set_protocols = int function (gnutls_session_t session, const(gnutls_datum_t)* protocols, uint protocols_size, uint flags);
        alias pgnutls_key_generate = int function (gnutls_datum_t* key, uint key_size);
        alias pgnutls_priority_init = int function (gnutls_priority_t* priority_cache, const(char)* priorities, const(char*)* err_pos);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_priority_init2 = int function (gnutls_priority_t* priority_cache, const(char)* priorities, const(char*)* err_pos, uint flags);

        alias pgnutls_priority_deinit = void function (gnutls_priority_t priority_cache);
        alias pgnutls_priority_get_cipher_suite_index = int function (gnutls_priority_t pcache, uint idx, uint* sidx);
        alias pgnutls_priority_string_list = const(char)* function (uint iter, uint flags);
        alias pgnutls_priority_set = int function (gnutls_session_t session, gnutls_priority_t priority);
        alias pgnutls_priority_set_direct = int function (gnutls_session_t session, const(char)* priorities, const(char*)* err_pos);
        alias pgnutls_priority_certificate_type_list = int function (gnutls_priority_t pcache, const(uint*)* list);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            alias pgnutls_priority_certificate_type_list2 = int function (gnutls_priority_t pcache, const(uint*)* list, gnutls_ctype_target_t target);

        alias pgnutls_priority_sign_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_protocol_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_ecc_curve_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_group_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_kx_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_cipher_list = int function (gnutls_priority_t pcache, const(uint*)* list);
        alias pgnutls_priority_mac_list = int function (gnutls_priority_t pcache, const(uint*)* list);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            alias pgnutls_get_system_config_file = const(char)* function ();

        alias pgnutls_set_default_priority = int function (gnutls_session_t session);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_set_default_priority_append = int function (gnutls_session_t session, const(char)* add_prio, const(char*)* err_pos, uint flags);

        alias pgnutls_cipher_suite_get_name = const(char)* function (gnutls_kx_algorithm_t kx_algorithm, gnutls_cipher_algorithm_t cipher_algorithm, gnutls_mac_algorithm_t mac_algorithm);
        alias pgnutls_protocol_get_version = gnutls_protocol_t function (gnutls_session_t session);
        alias pgnutls_protocol_get_name = const(char)* function (gnutls_protocol_t version_);
        alias pgnutls_session_set_data = int function (gnutls_session_t session, const(void)* session_data, size_t session_data_size);
        alias pgnutls_session_get_data = int function (gnutls_session_t session, void* session_data, size_t* session_data_size);
        alias pgnutls_session_get_data2 = int function (gnutls_session_t session, gnutls_datum_t* data);
        alias pgnutls_session_get_random = void function (gnutls_session_t session, gnutls_datum_t* client, gnutls_datum_t* server);
        alias pgnutls_session_get_master_secret = void function (gnutls_session_t session, gnutls_datum_t* secret);
        alias pgnutls_session_get_desc = char* function (gnutls_session_t session);
        alias pgnutls_session_set_verify_function = void function (gnutls_session_t session, int function () func);
        alias pgnutls_session_set_verify_cert = void function (gnutls_session_t session, const(char)* hostname, uint flags);
        alias pgnutls_session_set_verify_cert2 = void function (gnutls_session_t session, gnutls_typed_vdata_st* data, uint elements, uint flags);
        alias pgnutls_session_get_verify_cert_status = uint function (gnutls_session_t);
        alias pgnutls_session_set_premaster = int function (gnutls_session_t session, uint entity, gnutls_protocol_t version_, gnutls_kx_algorithm_t kx, gnutls_cipher_algorithm_t cipher, gnutls_mac_algorithm_t mac, gnutls_compression_method_t comp, const(gnutls_datum_t)* master, const(gnutls_datum_t)* session_id);
        alias pgnutls_session_get_id = int function (gnutls_session_t session, void* session_id, size_t* session_id_size);
        alias pgnutls_session_get_id2 = int function (gnutls_session_t session, gnutls_datum_t* session_id);
        alias pgnutls_session_set_id = int function (gnutls_session_t session, const(gnutls_datum_t)* sid);
        alias pgnutls_session_channel_binding = int function (gnutls_session_t session, gnutls_channel_binding_t cbtype, gnutls_datum_t* cb);
        alias pgnutls_session_is_resumed = int function (gnutls_session_t session);
        alias pgnutls_session_resumption_requested = int function (gnutls_session_t session);
        alias pgnutls_db_set_cache_expiration = void function (gnutls_session_t session, int seconds);
        alias pgnutls_db_get_default_cache_expiration = uint function ();
        alias pgnutls_db_remove_session = void function (gnutls_session_t session);
        alias pgnutls_db_set_retrieve_function = void function (gnutls_session_t session, gnutls_db_retr_func retr_func);
        alias pgnutls_db_set_remove_function = void function (gnutls_session_t session, gnutls_db_remove_func rem_func);
        alias pgnutls_db_set_store_function = void function (gnutls_session_t session, gnutls_db_store_func store_func);
        alias pgnutls_db_set_ptr = void function (gnutls_session_t session, void* ptr);
        alias pgnutls_db_get_ptr = void* function (gnutls_session_t session);
        alias pgnutls_db_check_entry = int function (gnutls_session_t session, gnutls_datum_t session_entry);
        alias pgnutls_db_check_entry_time = time_t function (gnutls_datum_t* entry);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            alias pgnutls_db_check_entry_expire_time = time_t function (gnutls_datum_t* entry);

        alias pgnutls_handshake_set_hook_function = void function (gnutls_session_t session, uint htype, int when, gnutls_handshake_hook_func func);
        alias pgnutls_handshake_set_post_client_hello_function = void function (gnutls_session_t session, gnutls_handshake_simple_hook_func func);
        alias pgnutls_handshake_set_max_packet_length = void function (gnutls_session_t session, size_t max);
        alias pgnutls_check_version = const(char)* function (const(char)* req_version);
        alias pgnutls_credentials_clear = void function (gnutls_session_t session);
        alias pgnutls_credentials_set = int function (gnutls_session_t session, gnutls_credentials_type_t type, void* cred);
        alias pgnutls_credentials_get = int function (gnutls_session_t session, gnutls_credentials_type_t type, void** cred);
        alias pgnutls_anon_free_server_credentials = void function (gnutls_anon_server_credentials_t sc);
        alias pgnutls_anon_allocate_server_credentials = int function (gnutls_anon_server_credentials_t* sc);
        alias pgnutls_anon_set_server_dh_params = void function (gnutls_anon_server_credentials_t res, gnutls_dh_params_t dh_params);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            alias pgnutls_anon_set_server_known_dh_params = int function (gnutls_anon_server_credentials_t res, gnutls_sec_param_t sec_param);

        alias pgnutls_anon_set_server_params_function = void function (gnutls_anon_server_credentials_t res, int function () func);
        alias pgnutls_anon_free_client_credentials = void function (gnutls_anon_client_credentials_t sc);
        alias pgnutls_anon_allocate_client_credentials = int function (gnutls_anon_client_credentials_t* sc);
        alias pgnutls_certificate_free_credentials = void function (gnutls_certificate_credentials_t sc);
        alias pgnutls_certificate_allocate_credentials = int function (gnutls_certificate_credentials_t* res);
        alias pgnutls_certificate_get_issuer = int function (gnutls_certificate_credentials_t sc, gnutls_x509_crt_t cert, gnutls_x509_crt_t* issuer, uint flags);
        alias pgnutls_certificate_get_crt_raw = int function (gnutls_certificate_credentials_t sc, uint idx1, uint idx2, gnutls_datum_t* cert);
        alias pgnutls_certificate_free_keys = void function (gnutls_certificate_credentials_t sc);
        alias pgnutls_certificate_free_cas = void function (gnutls_certificate_credentials_t sc);
        alias pgnutls_certificate_free_ca_names = void function (gnutls_certificate_credentials_t sc);
        alias pgnutls_certificate_free_crls = void function (gnutls_certificate_credentials_t sc);
        alias pgnutls_certificate_set_dh_params = void function (gnutls_certificate_credentials_t res, gnutls_dh_params_t dh_params);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            alias pgnutls_certificate_set_known_dh_params = int function (gnutls_certificate_credentials_t res, gnutls_sec_param_t sec_param);

        alias pgnutls_certificate_set_verify_flags = void function (gnutls_certificate_credentials_t res, uint flags);
        alias pgnutls_certificate_get_verify_flags = uint function (gnutls_certificate_credentials_t res);
        alias pgnutls_certificate_set_flags = void function (gnutls_certificate_credentials_t, uint flags);
        alias pgnutls_certificate_set_verify_limits = void function (gnutls_certificate_credentials_t res, uint max_bits, uint max_depth);
        alias pgnutls_certificate_set_x509_system_trust = int function (gnutls_certificate_credentials_t cred);
        alias pgnutls_certificate_set_x509_trust_file = int function (gnutls_certificate_credentials_t cred, const(char)* cafile, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_trust_dir = int function (gnutls_certificate_credentials_t cred, const(char)* ca_dir, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_trust_mem = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* ca, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_crl_file = int function (gnutls_certificate_credentials_t res, const(char)* crlfile, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_crl_mem = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* CRL, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_key_file = int function (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_key_file2 = int function (gnutls_certificate_credentials_t res, const(char)* certfile, const(char)* keyfile, gnutls_x509_crt_fmt_t type, const(char)* pass, uint flags);
        alias pgnutls_certificate_set_x509_key_mem = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, gnutls_x509_crt_fmt_t type);
        alias pgnutls_certificate_set_x509_key_mem2 = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* cert, const(gnutls_datum_t)* key, gnutls_x509_crt_fmt_t type, const(char)* pass, uint flags);
        alias pgnutls_certificate_send_x509_rdn_sequence = void function (gnutls_session_t session, int status);
        alias pgnutls_certificate_set_x509_simple_pkcs12_file = int function (gnutls_certificate_credentials_t res, const(char)* pkcs12file, gnutls_x509_crt_fmt_t type, const(char)* password);
        alias pgnutls_certificate_set_x509_simple_pkcs12_mem = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* p12blob, gnutls_x509_crt_fmt_t type, const(char)* password);
        alias pgnutls_certificate_set_x509_key = int function (gnutls_certificate_credentials_t res, gnutls_x509_crt_t* cert_list, int cert_list_size, gnutls_x509_privkey_t key);
        alias pgnutls_certificate_set_x509_trust = int function (gnutls_certificate_credentials_t res, gnutls_x509_crt_t* ca_list, int ca_list_size);
        alias pgnutls_certificate_set_x509_crl = int function (gnutls_certificate_credentials_t res, gnutls_x509_crl_t* crl_list, int crl_list_size);
        alias pgnutls_certificate_get_x509_key = int function (gnutls_certificate_credentials_t res, uint index, gnutls_x509_privkey_t* key);
        alias pgnutls_certificate_get_x509_crt = int function (gnutls_certificate_credentials_t res, uint index, gnutls_x509_crt_t** crt_list, uint* crt_list_size);
        alias pgnutls_certificate_set_ocsp_status_request_function = void function (gnutls_certificate_credentials_t res, gnutls_status_request_ocsp_func ocsp_func, void* ptr);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            alias pgnutls_certificate_set_ocsp_status_request_function2 = int function (gnutls_certificate_credentials_t res, uint idx, gnutls_status_request_ocsp_func ocsp_func, void* ptr);

        alias pgnutls_certificate_set_ocsp_status_request_file = int function (gnutls_certificate_credentials_t res, const(char)* response_file, uint idx);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            alias pgnutls_certificate_set_ocsp_status_request_file2 = int function (gnutls_certificate_credentials_t res, const(char)* response_file, uint idx, gnutls_x509_crt_fmt_t fmt);
            alias pgnutls_certificate_set_ocsp_status_request_mem = int function (gnutls_certificate_credentials_t res, const(gnutls_datum_t)* resp, uint idx, gnutls_x509_crt_fmt_t fmt);
            alias pgnutls_certificate_get_ocsp_expiration = time_t function (gnutls_certificate_credentials_t sc, uint idx, int oidx, uint flags);
        }

        alias pgnutls_ocsp_status_request_enable_client = int function (gnutls_session_t session, gnutls_datum_t* responder_id, size_t responder_id_size, gnutls_datum_t* request_extensions);
        alias pgnutls_ocsp_status_request_get = int function (gnutls_session_t session, gnutls_datum_t* response);
        alias pgnutls_ocsp_status_request_is_checked = uint function (gnutls_session_t session, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_ocsp_status_request_get2 = int function (gnutls_session_t session, uint idx, gnutls_datum_t* response);

        alias pgnutls_certificate_set_rawpk_key_mem = int function (gnutls_certificate_credentials_t cred, const(gnutls_datum_t)* spki, const(gnutls_datum_t)* pkey, gnutls_x509_crt_fmt_t format, const(char)* pass, uint key_usage, const(char*)* names, uint names_length, uint flags);
        alias pgnutls_certificate_set_rawpk_key_file = int function (gnutls_certificate_credentials_t cred, const(char)* rawpkfile, const(char)* privkeyfile, gnutls_x509_crt_fmt_t format, const(char)* pass, uint key_usage, const(char*)* names, uint names_length, uint privkey_flags, uint pkcs11_flags);
        alias pgnutls_global_init = int function ();
        alias pgnutls_global_deinit = void function ();
        alias pgnutls_global_set_mutex = void function (mutex_init_func init, mutex_deinit_func deinit, mutex_lock_func lock, mutex_unlock_func unlock);
        alias pgnutls_global_set_time_function = void function (gnutls_time_func time_func);
        alias pgnutls_memset = void function (void* data, int c, size_t size);
        alias pgnutls_memcmp = int function (const(void)* s1, const(void)* s2, size_t n);
        alias pgnutls_global_set_log_function = void function (gnutls_log_func log_func);
        alias pgnutls_global_set_audit_log_function = void function (gnutls_audit_log_func log_func);
        alias pgnutls_global_set_log_level = void function (int level);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            alias pgnutls_session_get_keylog_function = gnutls_keylog_func function (const gnutls_session_t session);
            alias pgnutls_session_set_keylog_function = void function (gnutls_session_t session, gnutls_keylog_func func);
        }

        alias pgnutls_dh_params_init = int function (gnutls_dh_params_t* dh_params);
        alias pgnutls_dh_params_deinit = void function (gnutls_dh_params_t dh_params);
        alias pgnutls_dh_params_import_raw = int function (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* generator);
        alias pgnutls_dh_params_import_dsa = int function (gnutls_dh_params_t dh_params, gnutls_x509_privkey_t key);
        alias pgnutls_dh_params_import_raw2 = int function (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* generator, uint key_bits);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            alias pgnutls_dh_params_import_raw3 = int function (gnutls_dh_params_t dh_params, const(gnutls_datum_t)* prime, const(gnutls_datum_t)* q, const(gnutls_datum_t)* generator);

        alias pgnutls_dh_params_import_pkcs3 = int function (gnutls_dh_params_t params, const(gnutls_datum_t)* pkcs3_params, gnutls_x509_crt_fmt_t format);
        alias pgnutls_dh_params_generate2 = int function (gnutls_dh_params_t params, uint bits);
        alias pgnutls_dh_params_export_pkcs3 = int function (gnutls_dh_params_t params, gnutls_x509_crt_fmt_t format, ubyte* params_data, size_t* params_data_size);
        alias pgnutls_dh_params_export2_pkcs3 = int function (gnutls_dh_params_t params, gnutls_x509_crt_fmt_t format, gnutls_datum_t* out_);
        alias pgnutls_dh_params_export_raw = int function (gnutls_dh_params_t params, gnutls_datum_t* prime, gnutls_datum_t* generator, uint* bits);
        alias pgnutls_dh_params_cpy = int function (gnutls_dh_params_t dst, gnutls_dh_params_t src);
        alias pgnutls_system_recv_timeout = int function (gnutls_transport_ptr_t ptr, uint ms);
        alias pgnutls_transport_set_int2 = void function (gnutls_session_t session, int r, int s);
        alias pgnutls_transport_get_int2 = void function (gnutls_session_t session, int* r, int* s);
        alias pgnutls_transport_get_int = int function (gnutls_session_t session);
        alias pgnutls_transport_set_ptr = void function (gnutls_session_t session, gnutls_transport_ptr_t ptr);
        alias pgnutls_transport_set_ptr2 = void function (gnutls_session_t session, gnutls_transport_ptr_t recv_ptr, gnutls_transport_ptr_t send_ptr);
        alias pgnutls_transport_get_ptr = gnutls_transport_ptr_t function (gnutls_session_t session);
        alias pgnutls_transport_get_ptr2 = void function (gnutls_session_t session, gnutls_transport_ptr_t* recv_ptr, gnutls_transport_ptr_t* send_ptr);
        alias pgnutls_transport_set_vec_push_function = void function (gnutls_session_t session, gnutls_vec_push_func vec_func);
        alias pgnutls_transport_set_push_function = void function (gnutls_session_t session, gnutls_push_func push_func);
        alias pgnutls_transport_set_pull_function = void function (gnutls_session_t session, gnutls_pull_func pull_func);
        alias pgnutls_transport_set_pull_timeout_function = void function (gnutls_session_t session, gnutls_pull_timeout_func func);
        alias pgnutls_transport_set_errno_function = void function (gnutls_session_t session, gnutls_errno_func errno_func);
        alias pgnutls_transport_set_errno = void function (gnutls_session_t session, int err);
        alias pgnutls_session_set_ptr = void function (gnutls_session_t session, void* ptr);
        alias pgnutls_session_get_ptr = void* function (gnutls_session_t session);
        alias pgnutls_openpgp_send_cert = void function (gnutls_session_t session, gnutls_openpgp_crt_status_t status);
        alias pgnutls_fingerprint = int function (gnutls_digest_algorithm_t algo, const(gnutls_datum_t)* data, void* result, size_t* result_size);
        alias pgnutls_random_art = int function (gnutls_random_art_t type, const(char)* key_type, uint key_size, void* fpr, size_t fpr_size, gnutls_datum_t* art);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_9)
        {
            alias pgnutls_idna_map = int function (const(char)* input, uint ilen, gnutls_datum_t* out_, uint flags);
            alias pgnutls_idna_reverse_map = int function (const(char)* input, uint ilen, gnutls_datum_t* out_, uint flags);
        }

        alias pgnutls_srp_free_client_credentials = void function (gnutls_srp_client_credentials_t sc);
        alias pgnutls_srp_allocate_client_credentials = int function (gnutls_srp_client_credentials_t* sc);
        alias pgnutls_srp_set_client_credentials = int function (gnutls_srp_client_credentials_t res, const(char)* username, const(char)* password);
        alias pgnutls_srp_free_server_credentials = void function (gnutls_srp_server_credentials_t sc);
        alias pgnutls_srp_allocate_server_credentials = int function (gnutls_srp_server_credentials_t* sc);
        alias pgnutls_srp_set_server_credentials_file = int function (gnutls_srp_server_credentials_t res, const(char)* password_file, const(char)* password_conf_file);
        alias pgnutls_srp_server_get_username = const(char)* function (gnutls_session_t session);
        alias pgnutls_srp_set_prime_bits = void function (gnutls_session_t session, uint bits);
        alias pgnutls_srp_verifier = int function (const(char)* username, const(char)* password, const(gnutls_datum_t)* salt, const(gnutls_datum_t)* generator, const(gnutls_datum_t)* prime, gnutls_datum_t* res);
        alias pgnutls_srp_set_server_credentials_function = void function (gnutls_srp_server_credentials_t cred, int function () func);
        alias pgnutls_srp_set_client_credentials_function = void function (gnutls_srp_client_credentials_t cred, int function () func);
        alias pgnutls_srp_base64_encode = int function (const(gnutls_datum_t)* data, char* result, size_t* result_size);
        alias pgnutls_srp_base64_encode2 = int function (const(gnutls_datum_t)* data, gnutls_datum_t* result);
        alias pgnutls_srp_base64_decode = int function (const(gnutls_datum_t)* b64_data, char* result, size_t* result_size);
        alias pgnutls_srp_base64_decode2 = int function (const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);
        alias pgnutls_srp_set_server_fake_salt_seed = void function (gnutls_srp_server_credentials_t sc, const(gnutls_datum_t)* seed, uint salt_length);
        alias pgnutls_psk_free_client_credentials = void function (gnutls_psk_client_credentials_t sc);
        alias pgnutls_psk_allocate_client_credentials = int function (gnutls_psk_client_credentials_t* sc);
        alias pgnutls_psk_set_client_credentials = int function (gnutls_psk_client_credentials_t res, const(char)* username, const(gnutls_datum_t)* key, gnutls_psk_key_flags flags);
        alias pgnutls_psk_free_server_credentials = void function (gnutls_psk_server_credentials_t sc);
        alias pgnutls_psk_allocate_server_credentials = int function (gnutls_psk_server_credentials_t* sc);
        alias pgnutls_psk_set_server_credentials_file = int function (gnutls_psk_server_credentials_t res, const(char)* password_file);
        alias pgnutls_psk_set_server_credentials_hint = int function (gnutls_psk_server_credentials_t res, const(char)* hint);
        alias pgnutls_psk_server_get_username = const(char)* function (gnutls_session_t session);
        alias pgnutls_psk_client_get_hint = const(char)* function (gnutls_session_t session);
        alias pgnutls_psk_set_server_credentials_function = void function (gnutls_psk_server_credentials_t cred, int function () func);
        alias pgnutls_psk_set_client_credentials_function = void function (gnutls_psk_client_credentials_t cred, int function () func);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            alias pgnutls_psk_set_client_credentials2 = int function (gnutls_psk_client_credentials_t res, const(gnutls_datum_t)* username, const(gnutls_datum_t)* key, gnutls_psk_key_flags flags);
            alias pgnutls_psk_server_get_username2 = int function (gnutls_session_t session, gnutls_datum_t* out_);
            alias pgnutls_psk_set_server_credentials_function2 = void function (gnutls_psk_server_credentials_t cred, int function () func);
            alias pgnutls_psk_set_client_credentials_function2 = void function (gnutls_psk_client_credentials_t cred, int function () func);
        }

        alias pgnutls_hex_encode = int function (const(gnutls_datum_t)* data, char* result, size_t* result_size);
        alias pgnutls_hex_decode = int function (const(gnutls_datum_t)* hex_data, void* result, size_t* result_size);
        alias pgnutls_hex_encode2 = int function (const(gnutls_datum_t)* data, gnutls_datum_t* result);
        alias pgnutls_hex_decode2 = int function (const(gnutls_datum_t)* data, gnutls_datum_t* result);
        alias pgnutls_psk_set_server_dh_params = void function (gnutls_psk_server_credentials_t res, gnutls_dh_params_t dh_params);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            alias pgnutls_psk_set_server_known_dh_params = int function (gnutls_psk_server_credentials_t res, gnutls_sec_param_t sec_param);

        alias pgnutls_psk_set_server_params_function = void function (gnutls_psk_server_credentials_t res, int function () func);
        alias pgnutls_auth_get_type = gnutls_credentials_type_t function (gnutls_session_t session);
        alias pgnutls_auth_server_get_type = gnutls_credentials_type_t function (gnutls_session_t session);
        alias pgnutls_auth_client_get_type = gnutls_credentials_type_t function (gnutls_session_t session);
        alias pgnutls_dh_set_prime_bits = void function (gnutls_session_t session, uint bits);
        alias pgnutls_dh_get_secret_bits = int function (gnutls_session_t session);
        alias pgnutls_dh_get_peers_public_bits = int function (gnutls_session_t session);
        alias pgnutls_dh_get_prime_bits = int function (gnutls_session_t session);
        alias pgnutls_dh_get_group = int function (gnutls_session_t session, gnutls_datum_t* raw_gen, gnutls_datum_t* raw_prime);
        alias pgnutls_dh_get_pubkey = int function (gnutls_session_t session, gnutls_datum_t* raw_key);
        alias pgnutls_certificate_set_retrieve_function = void function (gnutls_certificate_credentials_t cred, int function () func);
        alias pgnutls_certificate_set_verify_function = void function (gnutls_certificate_credentials_t cred, int function () func);
        alias pgnutls_certificate_server_set_request = void function (gnutls_session_t session, gnutls_certificate_request_t req);
        alias pgnutls_certificate_get_peers = const(gnutls_datum_t)* function (gnutls_session_t session, uint* list_size);
        alias pgnutls_certificate_get_ours = const(gnutls_datum_t)* function (gnutls_session_t session);
        alias pgnutls_certificate_get_peers_subkey_id = int function (gnutls_session_t session, gnutls_datum_t* id);
        alias pgnutls_certificate_activation_time_peers = time_t function (gnutls_session_t session);
        alias pgnutls_certificate_expiration_time_peers = time_t function (gnutls_session_t session);
        alias pgnutls_certificate_client_get_request_status = uint function (gnutls_session_t session);
        alias pgnutls_certificate_verify_peers2 = int function (gnutls_session_t session, uint* status);
        alias pgnutls_certificate_verify_peers3 = int function (gnutls_session_t session, const(char)* hostname, uint* status);
        alias pgnutls_certificate_verify_peers = int function (gnutls_session_t session, gnutls_typed_vdata_st* data, uint elements, uint* status);
        alias pgnutls_certificate_verification_status_print = int function (uint status, gnutls_certificate_type_t type, gnutls_datum_t* out_, uint flags);
        alias pgnutls_pem_base64_encode = int function (const(char)* msg, const(gnutls_datum_t)* data, char* result, size_t* result_size);
        alias pgnutls_pem_base64_decode = int function (const(char)* header, const(gnutls_datum_t)* b64_data, ubyte* result, size_t* result_size);
        alias pgnutls_pem_base64_encode2 = int function (const(char)* msg, const(gnutls_datum_t)* data, gnutls_datum_t* result);
        alias pgnutls_pem_base64_decode2 = int function (const(char)* header, const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            alias pgnutls_base64_encode2 = int function (const(gnutls_datum_t)* data, gnutls_datum_t* result);
            alias pgnutls_base64_decode2 = int function (const(gnutls_datum_t)* b64_data, gnutls_datum_t* result);
        }

        alias pgnutls_certificate_set_params_function = void function (gnutls_certificate_credentials_t res, int function () func);
        alias pgnutls_anon_set_params_function = void function (gnutls_anon_server_credentials_t res, int function () func);
        alias pgnutls_psk_set_params_function = void function (gnutls_psk_server_credentials_t res, int function () func);
        alias pgnutls_hex2bin = int function (const(char)* hex_data, size_t hex_size, void* bin_data, size_t* bin_size);
        alias pgnutls_tdb_init = int function (gnutls_tdb_t* tdb);
        alias pgnutls_tdb_set_store_func = void function (gnutls_tdb_t tdb, gnutls_tdb_store_func store);
        alias pgnutls_tdb_set_store_commitment_func = void function (gnutls_tdb_t tdb, gnutls_tdb_store_commitment_func cstore);
        alias pgnutls_tdb_set_verify_func = void function (gnutls_tdb_t tdb, gnutls_tdb_verify_func verify);
        alias pgnutls_tdb_deinit = void function (gnutls_tdb_t tdb);
        alias pgnutls_verify_stored_pubkey = int function (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_certificate_type_t cert_type, const(gnutls_datum_t)* cert, uint flags);
        alias pgnutls_store_commitment = int function (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_digest_algorithm_t hash_algo, const(gnutls_datum_t)* hash, time_t expiration, uint flags);
        alias pgnutls_store_pubkey = int function (const(char)* db_name, gnutls_tdb_t tdb, const(char)* host, const(char)* service, gnutls_certificate_type_t cert_type, const(gnutls_datum_t)* cert, time_t expiration, uint flags);
        alias pgnutls_load_file = int function (const(char)* filename, gnutls_datum_t* data);
        alias pgnutls_url_is_supported = uint function (const(char)* url);
        alias pgnutls_certificate_set_pin_function = void function (gnutls_certificate_credentials_t, gnutls_pin_callback_t fn, void* userdata);
        alias pgnutls_buffer_append_data = int function (gnutls_buffer_t, const(void)* data, size_t data_size);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            alias pgnutls_utf8_password_normalize = int function (const(ubyte)* password, uint password_len, gnutls_datum_t* out_, uint flags);

        alias pgnutls_ext_set_data = void function (gnutls_session_t session, uint type, gnutls_ext_priv_data_t);
        alias pgnutls_ext_get_data = int function (gnutls_session_t session, uint type, gnutls_ext_priv_data_t*);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            alias pgnutls_ext_get_current_msg = uint function (gnutls_session_t session);
            alias pgnutls_ext_raw_parse = int function (void* ctx, gnutls_ext_raw_process_func cb, const(gnutls_datum_t)* data, uint flags);
        }

        alias pgnutls_ext_register = int function (const(char)* name, int type, gnutls_ext_parse_type_t parse_point, gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func, gnutls_ext_unpack_func unpack_func);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            alias pgnutls_session_ext_register = int function (gnutls_session_t, const(char)* name, int type, gnutls_ext_parse_type_t parse_point, gnutls_ext_recv_func recv_func, gnutls_ext_send_func send_func, gnutls_ext_deinit_data_func deinit_func, gnutls_ext_pack_func pack_func, gnutls_ext_unpack_func unpack_func, uint flags);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            alias pgnutls_ext_get_name = const(char)* function (uint ext);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_14)
            alias pgnutls_ext_get_name2 = const(char)* function (gnutls_session_t session, uint tls_id, gnutls_ext_parse_type_t parse_point);

        alias pgnutls_supplemental_register = int function (const(char)* name, gnutls_supplemental_data_format_type_t type, gnutls_supp_recv_func supp_recv_func, gnutls_supp_send_func supp_send_func);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            alias pgnutls_session_supplemental_register = int function (gnutls_session_t session, const(char)* name, gnutls_supplemental_data_format_type_t type, gnutls_supp_recv_func supp_recv_func, gnutls_supp_send_func supp_send_func, uint flags);

        alias pgnutls_supplemental_recv = void function (gnutls_session_t session, uint do_recv_supplemental);
        alias pgnutls_supplemental_send = void function (gnutls_session_t session, uint do_send_supplemental);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            alias pgnutls_anti_replay_init = int function (gnutls_anti_replay_t* anti_replay);
            alias pgnutls_anti_replay_deinit = void function (gnutls_anti_replay_t anti_replay);
            alias pgnutls_anti_replay_set_window = void function (gnutls_anti_replay_t anti_replay, uint window);
            alias pgnutls_anti_replay_enable = void function (gnutls_session_t session, gnutls_anti_replay_t anti_replay);
            alias pgnutls_anti_replay_set_add_function = void function (gnutls_anti_replay_t, gnutls_db_add_func add_func);
        }

        alias pgnutls_anti_replay_set_ptr = void function (gnutls_anti_replay_t, void* ptr);
        alias pgnutls_fips140_mode_enabled = uint function ();

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_fips140_set_mode = void function (gnutls_fips_mode_t mode, uint flags);
    }

    __gshared
    {
        pgnutls_pk_algorithm_get_name gnutls_pk_algorithm_get_name;
        pgnutls_init gnutls_init;
        pgnutls_deinit gnutls_deinit;
        pgnutls_bye gnutls_bye;
        pgnutls_handshake gnutls_handshake;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_reauth gnutls_reauth;

        pgnutls_handshake_set_timeout gnutls_handshake_set_timeout;
        pgnutls_rehandshake gnutls_rehandshake;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_session_key_update gnutls_session_key_update;

        pgnutls_alert_get gnutls_alert_get;
        pgnutls_alert_send gnutls_alert_send;
        pgnutls_alert_send_appropriate gnutls_alert_send_appropriate;
        pgnutls_alert_get_name gnutls_alert_get_name;
        pgnutls_alert_get_strname gnutls_alert_get_strname;
        pgnutls_pk_bits_to_sec_param gnutls_pk_bits_to_sec_param;
        pgnutls_sec_param_get_name gnutls_sec_param_get_name;
        pgnutls_sec_param_to_pk_bits gnutls_sec_param_to_pk_bits;
        pgnutls_sec_param_to_symmetric_bits gnutls_sec_param_to_symmetric_bits;
        pgnutls_ecc_curve_get_name gnutls_ecc_curve_get_name;
        pgnutls_ecc_curve_get_oid gnutls_ecc_curve_get_oid;
        pgnutls_group_get_name gnutls_group_get_name;
        pgnutls_ecc_curve_get_size gnutls_ecc_curve_get_size;
        pgnutls_ecc_curve_get gnutls_ecc_curve_get;
        pgnutls_group_get gnutls_group_get;
        pgnutls_cipher_get gnutls_cipher_get;
        pgnutls_kx_get gnutls_kx_get;
        pgnutls_mac_get gnutls_mac_get;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
            pgnutls_prf_hash_get gnutls_prf_hash_get;

        pgnutls_certificate_type_get gnutls_certificate_type_get;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            pgnutls_certificate_type_get2 gnutls_certificate_type_get2;

        pgnutls_sign_algorithm_get gnutls_sign_algorithm_get;
        pgnutls_sign_algorithm_get_client gnutls_sign_algorithm_get_client;
        pgnutls_sign_algorithm_get_requested gnutls_sign_algorithm_get_requested;
        pgnutls_cipher_get_name gnutls_cipher_get_name;
        pgnutls_mac_get_name gnutls_mac_get_name;
        pgnutls_digest_get_name gnutls_digest_get_name;
        pgnutls_digest_get_oid gnutls_digest_get_oid;
        pgnutls_kx_get_name gnutls_kx_get_name;
        pgnutls_certificate_type_get_name gnutls_certificate_type_get_name;
        pgnutls_pk_get_name gnutls_pk_get_name;
        pgnutls_pk_get_oid gnutls_pk_get_oid;
        pgnutls_sign_get_name gnutls_sign_get_name;
        pgnutls_sign_get_oid gnutls_sign_get_oid;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            pgnutls_gost_paramset_get_name gnutls_gost_paramset_get_name;
            pgnutls_gost_paramset_get_oid gnutls_gost_paramset_get_oid;
        }

        pgnutls_cipher_get_key_size gnutls_cipher_get_key_size;
        pgnutls_mac_get_key_size gnutls_mac_get_key_size;
        pgnutls_sign_is_secure gnutls_sign_is_secure;
        pgnutls_sign_is_secure2 gnutls_sign_is_secure2;
        pgnutls_sign_get_hash_algorithm gnutls_sign_get_hash_algorithm;
        pgnutls_sign_get_pk_algorithm gnutls_sign_get_pk_algorithm;
        pgnutls_pk_to_sign gnutls_pk_to_sign;
        pgnutls_sign_supports_pk_algorithm gnutls_sign_supports_pk_algorithm;
        pgnutls_mac_get_id gnutls_mac_get_id;
        pgnutls_digest_get_id gnutls_digest_get_id;
        pgnutls_cipher_get_id gnutls_cipher_get_id;
        pgnutls_kx_get_id gnutls_kx_get_id;
        pgnutls_protocol_get_id gnutls_protocol_get_id;
        pgnutls_certificate_type_get_id gnutls_certificate_type_get_id;
        pgnutls_pk_get_id gnutls_pk_get_id;
        pgnutls_sign_get_id gnutls_sign_get_id;
        pgnutls_ecc_curve_get_id gnutls_ecc_curve_get_id;
        pgnutls_ecc_curve_get_pk gnutls_ecc_curve_get_pk;
        pgnutls_group_get_id gnutls_group_get_id;
        pgnutls_oid_to_digest gnutls_oid_to_digest;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            pgnutls_oid_to_mac gnutls_oid_to_mac;

        pgnutls_oid_to_pk gnutls_oid_to_pk;
        pgnutls_oid_to_sign gnutls_oid_to_sign;
        pgnutls_oid_to_ecc_curve gnutls_oid_to_ecc_curve;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_oid_to_gost_paramset gnutls_oid_to_gost_paramset;

        pgnutls_ecc_curve_list gnutls_ecc_curve_list;
        pgnutls_group_list gnutls_group_list;
        pgnutls_cipher_list gnutls_cipher_list;
        pgnutls_mac_list gnutls_mac_list;
        pgnutls_digest_list gnutls_digest_list;
        pgnutls_protocol_list gnutls_protocol_list;
        pgnutls_certificate_type_list gnutls_certificate_type_list;
        pgnutls_kx_list gnutls_kx_list;
        pgnutls_pk_list gnutls_pk_list;
        pgnutls_sign_list gnutls_sign_list;
        pgnutls_cipher_suite_info gnutls_cipher_suite_info;
        pgnutls_error_is_fatal gnutls_error_is_fatal;
        pgnutls_error_to_alert gnutls_error_to_alert;
        pgnutls_perror gnutls_perror;
        pgnutls_strerror gnutls_strerror;
        pgnutls_strerror_name gnutls_strerror_name;
        pgnutls_handshake_set_private_extensions gnutls_handshake_set_private_extensions;
        pgnutls_handshake_set_random gnutls_handshake_set_random;
        pgnutls_handshake_get_last_out gnutls_handshake_get_last_out;
        pgnutls_handshake_get_last_in gnutls_handshake_get_last_in;
        pgnutls_heartbeat_ping gnutls_heartbeat_ping;
        pgnutls_heartbeat_pong gnutls_heartbeat_pong;
        pgnutls_record_set_timeout gnutls_record_set_timeout;
        pgnutls_record_disable_padding gnutls_record_disable_padding;
        pgnutls_record_cork gnutls_record_cork;
        pgnutls_record_uncork gnutls_record_uncork;
        pgnutls_record_discard_queued gnutls_record_discard_queued;
        pgnutls_record_get_state gnutls_record_get_state;
        pgnutls_record_set_state gnutls_record_set_state;
        pgnutls_range_split gnutls_range_split;
        pgnutls_record_send gnutls_record_send;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_record_send2 gnutls_record_send2;

        pgnutls_record_send_range gnutls_record_send_range;
        pgnutls_record_recv gnutls_record_recv;
        pgnutls_record_recv_packet gnutls_record_recv_packet;
        pgnutls_packet_get gnutls_packet_get;
        pgnutls_packet_deinit gnutls_packet_deinit;
        pgnutls_record_recv_seq gnutls_record_recv_seq;
        pgnutls_record_overhead_size gnutls_record_overhead_size;
        pgnutls_est_record_overhead_size gnutls_est_record_overhead_size;
        pgnutls_session_enable_compatibility_mode gnutls_session_enable_compatibility_mode;
        pgnutls_record_can_use_length_hiding gnutls_record_can_use_length_hiding;
        pgnutls_record_get_direction gnutls_record_get_direction;
        pgnutls_record_get_max_size gnutls_record_get_max_size;
        pgnutls_record_set_max_size gnutls_record_set_max_size;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            pgnutls_record_set_max_recv_size gnutls_record_set_max_recv_size;

        pgnutls_record_check_pending gnutls_record_check_pending;
        pgnutls_record_check_corked gnutls_record_check_corked;


        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            pgnutls_record_set_max_early_data_size gnutls_record_set_max_early_data_size;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            pgnutls_record_get_max_early_data_size gnutls_record_get_max_early_data_size;
            pgnutls_record_send_early_data gnutls_record_send_early_data;
            pgnutls_record_recv_early_data gnutls_record_recv_early_data;
        }

        pgnutls_session_force_valid gnutls_session_force_valid;
        pgnutls_prf gnutls_prf;
        pgnutls_prf_rfc5705 gnutls_prf_rfc5705;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            pgnutls_prf_early gnutls_prf_early;

        pgnutls_prf_raw gnutls_prf_raw;
        pgnutls_server_name_set gnutls_server_name_set;
        pgnutls_server_name_get gnutls_server_name_get;
        pgnutls_heartbeat_get_timeout gnutls_heartbeat_get_timeout;
        pgnutls_heartbeat_set_timeouts gnutls_heartbeat_set_timeouts;
        pgnutls_heartbeat_enable gnutls_heartbeat_enable;
        pgnutls_heartbeat_allowed gnutls_heartbeat_allowed;
        pgnutls_safe_renegotiation_status gnutls_safe_renegotiation_status;
        pgnutls_session_ext_master_secret_status gnutls_session_ext_master_secret_status;
        pgnutls_session_etm_status gnutls_session_etm_status;
        pgnutls_session_get_flags gnutls_session_get_flags;
        pgnutls_supplemental_get_name gnutls_supplemental_get_name;
        pgnutls_session_ticket_key_generate gnutls_session_ticket_key_generate;
        pgnutls_session_ticket_enable_client gnutls_session_ticket_enable_client;
        pgnutls_session_ticket_enable_server gnutls_session_ticket_enable_server;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_session_ticket_send gnutls_session_ticket_send;

        pgnutls_srtp_set_profile gnutls_srtp_set_profile;
        pgnutls_srtp_set_profile_direct gnutls_srtp_set_profile_direct;
        pgnutls_srtp_get_selected_profile gnutls_srtp_get_selected_profile;
        pgnutls_srtp_get_profile_name gnutls_srtp_get_profile_name;
        pgnutls_srtp_get_profile_id gnutls_srtp_get_profile_id;
        pgnutls_srtp_get_keys gnutls_srtp_get_keys;
        pgnutls_srtp_set_mki gnutls_srtp_set_mki;
        pgnutls_srtp_get_mki gnutls_srtp_get_mki;
        pgnutls_alpn_get_selected_protocol gnutls_alpn_get_selected_protocol;
        pgnutls_alpn_set_protocols gnutls_alpn_set_protocols;
        pgnutls_key_generate gnutls_key_generate;
        pgnutls_priority_init gnutls_priority_init;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_priority_init2 gnutls_priority_init2;

        pgnutls_priority_deinit gnutls_priority_deinit;
        pgnutls_priority_get_cipher_suite_index gnutls_priority_get_cipher_suite_index;
        pgnutls_priority_string_list gnutls_priority_string_list;
        pgnutls_priority_set gnutls_priority_set;
        pgnutls_priority_set_direct gnutls_priority_set_direct;
        pgnutls_priority_certificate_type_list gnutls_priority_certificate_type_list;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            pgnutls_priority_certificate_type_list2 gnutls_priority_certificate_type_list2;

        pgnutls_priority_sign_list gnutls_priority_sign_list;
        pgnutls_priority_protocol_list gnutls_priority_protocol_list;
        pgnutls_priority_ecc_curve_list gnutls_priority_ecc_curve_list;
        pgnutls_priority_group_list gnutls_priority_group_list;
        pgnutls_priority_kx_list gnutls_priority_kx_list;
        pgnutls_priority_cipher_list gnutls_priority_cipher_list;
        pgnutls_priority_mac_list gnutls_priority_mac_list;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            pgnutls_get_system_config_file gnutls_get_system_config_file;

        pgnutls_set_default_priority gnutls_set_default_priority;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_set_default_priority_append gnutls_set_default_priority_append;

        pgnutls_cipher_suite_get_name gnutls_cipher_suite_get_name;
        pgnutls_protocol_get_version gnutls_protocol_get_version;
        pgnutls_protocol_get_name gnutls_protocol_get_name;
        pgnutls_session_set_data gnutls_session_set_data;
        pgnutls_session_get_data gnutls_session_get_data;
        pgnutls_session_get_data2 gnutls_session_get_data2;
        pgnutls_session_get_random gnutls_session_get_random;
        pgnutls_session_get_master_secret gnutls_session_get_master_secret;
        pgnutls_session_get_desc gnutls_session_get_desc;
        pgnutls_session_set_verify_function gnutls_session_set_verify_function;
        pgnutls_session_set_verify_cert gnutls_session_set_verify_cert;
        pgnutls_session_set_verify_cert2 gnutls_session_set_verify_cert2;
        pgnutls_session_get_verify_cert_status gnutls_session_get_verify_cert_status;
        pgnutls_session_set_premaster gnutls_session_set_premaster;
        pgnutls_session_get_id gnutls_session_get_id;
        pgnutls_session_get_id2 gnutls_session_get_id2;
        pgnutls_session_set_id gnutls_session_set_id;
        pgnutls_session_channel_binding gnutls_session_channel_binding;
        pgnutls_session_is_resumed gnutls_session_is_resumed;
        pgnutls_session_resumption_requested gnutls_session_resumption_requested;
        pgnutls_db_set_cache_expiration gnutls_db_set_cache_expiration;
        pgnutls_db_get_default_cache_expiration gnutls_db_get_default_cache_expiration;
        pgnutls_db_remove_session gnutls_db_remove_session;
        pgnutls_db_set_retrieve_function gnutls_db_set_retrieve_function;
        pgnutls_db_set_remove_function gnutls_db_set_remove_function;
        pgnutls_db_set_store_function gnutls_db_set_store_function;
        pgnutls_db_set_ptr gnutls_db_set_ptr;
        pgnutls_db_get_ptr gnutls_db_get_ptr;
        pgnutls_db_check_entry gnutls_db_check_entry;
        pgnutls_db_check_entry_time gnutls_db_check_entry_time;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            pgnutls_db_check_entry_expire_time gnutls_db_check_entry_expire_time;

        pgnutls_handshake_set_hook_function gnutls_handshake_set_hook_function;
        pgnutls_handshake_set_post_client_hello_function gnutls_handshake_set_post_client_hello_function;
        pgnutls_handshake_set_max_packet_length gnutls_handshake_set_max_packet_length;
        pgnutls_check_version gnutls_check_version;
        pgnutls_credentials_clear gnutls_credentials_clear;
        pgnutls_credentials_set gnutls_credentials_set;
        pgnutls_credentials_get gnutls_credentials_get;
        pgnutls_anon_free_server_credentials gnutls_anon_free_server_credentials;
        pgnutls_anon_allocate_server_credentials gnutls_anon_allocate_server_credentials;
        pgnutls_anon_set_server_dh_params gnutls_anon_set_server_dh_params;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            pgnutls_anon_set_server_known_dh_params gnutls_anon_set_server_known_dh_params;

        pgnutls_anon_set_server_params_function gnutls_anon_set_server_params_function;
        pgnutls_anon_free_client_credentials gnutls_anon_free_client_credentials;
        pgnutls_anon_allocate_client_credentials gnutls_anon_allocate_client_credentials;
        pgnutls_certificate_free_credentials gnutls_certificate_free_credentials;
        pgnutls_certificate_allocate_credentials gnutls_certificate_allocate_credentials;
        pgnutls_certificate_get_issuer gnutls_certificate_get_issuer;
        pgnutls_certificate_get_crt_raw gnutls_certificate_get_crt_raw;
        pgnutls_certificate_free_keys gnutls_certificate_free_keys;
        pgnutls_certificate_free_cas gnutls_certificate_free_cas;
        pgnutls_certificate_free_ca_names gnutls_certificate_free_ca_names;
        pgnutls_certificate_free_crls gnutls_certificate_free_crls;
        pgnutls_certificate_set_dh_params gnutls_certificate_set_dh_params;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            pgnutls_certificate_set_known_dh_params gnutls_certificate_set_known_dh_params;

        pgnutls_certificate_set_verify_flags gnutls_certificate_set_verify_flags;
        pgnutls_certificate_get_verify_flags gnutls_certificate_get_verify_flags;
        pgnutls_certificate_set_flags gnutls_certificate_set_flags;
        pgnutls_certificate_set_verify_limits gnutls_certificate_set_verify_limits;
        pgnutls_certificate_set_x509_system_trust gnutls_certificate_set_x509_system_trust;
        pgnutls_certificate_set_x509_trust_file gnutls_certificate_set_x509_trust_file;
        pgnutls_certificate_set_x509_trust_dir gnutls_certificate_set_x509_trust_dir;
        pgnutls_certificate_set_x509_trust_mem gnutls_certificate_set_x509_trust_mem;
        pgnutls_certificate_set_x509_crl_file gnutls_certificate_set_x509_crl_file;
        pgnutls_certificate_set_x509_crl_mem gnutls_certificate_set_x509_crl_mem;
        pgnutls_certificate_set_x509_key_file gnutls_certificate_set_x509_key_file;
        pgnutls_certificate_set_x509_key_file2 gnutls_certificate_set_x509_key_file2;
        pgnutls_certificate_set_x509_key_mem gnutls_certificate_set_x509_key_mem;
        pgnutls_certificate_set_x509_key_mem2 gnutls_certificate_set_x509_key_mem2;
        pgnutls_certificate_send_x509_rdn_sequence gnutls_certificate_send_x509_rdn_sequence;
        pgnutls_certificate_set_x509_simple_pkcs12_file gnutls_certificate_set_x509_simple_pkcs12_file;
        pgnutls_certificate_set_x509_simple_pkcs12_mem gnutls_certificate_set_x509_simple_pkcs12_mem;
        pgnutls_certificate_set_x509_key gnutls_certificate_set_x509_key;
        pgnutls_certificate_set_x509_trust gnutls_certificate_set_x509_trust;
        pgnutls_certificate_set_x509_crl gnutls_certificate_set_x509_crl;
        pgnutls_certificate_get_x509_key gnutls_certificate_get_x509_key;
        pgnutls_certificate_get_x509_crt gnutls_certificate_get_x509_crt;
        pgnutls_certificate_set_ocsp_status_request_function gnutls_certificate_set_ocsp_status_request_function;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            pgnutls_certificate_set_ocsp_status_request_function2 gnutls_certificate_set_ocsp_status_request_function2;

        pgnutls_certificate_set_ocsp_status_request_file gnutls_certificate_set_ocsp_status_request_file;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            pgnutls_certificate_set_ocsp_status_request_file2 gnutls_certificate_set_ocsp_status_request_file2;
            pgnutls_certificate_set_ocsp_status_request_mem gnutls_certificate_set_ocsp_status_request_mem;
            pgnutls_certificate_get_ocsp_expiration gnutls_certificate_get_ocsp_expiration;
        }

        pgnutls_ocsp_status_request_enable_client gnutls_ocsp_status_request_enable_client;
        pgnutls_ocsp_status_request_get gnutls_ocsp_status_request_get;
        pgnutls_ocsp_status_request_is_checked gnutls_ocsp_status_request_is_checked;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_ocsp_status_request_get2 gnutls_ocsp_status_request_get2;

        pgnutls_certificate_set_rawpk_key_mem gnutls_certificate_set_rawpk_key_mem;
        pgnutls_certificate_set_rawpk_key_file gnutls_certificate_set_rawpk_key_file;
        pgnutls_global_init gnutls_global_init;
        pgnutls_global_deinit gnutls_global_deinit;
        pgnutls_global_set_mutex gnutls_global_set_mutex;
        pgnutls_global_set_time_function gnutls_global_set_time_function;
        pgnutls_memset gnutls_memset;
        pgnutls_memcmp gnutls_memcmp;
        pgnutls_global_set_log_function gnutls_global_set_log_function;
        pgnutls_global_set_audit_log_function gnutls_global_set_audit_log_function;
        pgnutls_global_set_log_level gnutls_global_set_log_level;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            pgnutls_session_get_keylog_function gnutls_session_get_keylog_function;
            pgnutls_session_set_keylog_function gnutls_session_set_keylog_function;
        }

        pgnutls_dh_params_init gnutls_dh_params_init;
        pgnutls_dh_params_deinit gnutls_dh_params_deinit;
        pgnutls_dh_params_import_raw gnutls_dh_params_import_raw;
        pgnutls_dh_params_import_dsa gnutls_dh_params_import_dsa;
        pgnutls_dh_params_import_raw2 gnutls_dh_params_import_raw2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            pgnutls_dh_params_import_raw3 gnutls_dh_params_import_raw3;

        pgnutls_dh_params_import_pkcs3 gnutls_dh_params_import_pkcs3;
        pgnutls_dh_params_generate2 gnutls_dh_params_generate2;
        pgnutls_dh_params_export_pkcs3 gnutls_dh_params_export_pkcs3;
        pgnutls_dh_params_export2_pkcs3 gnutls_dh_params_export2_pkcs3;
        pgnutls_dh_params_export_raw gnutls_dh_params_export_raw;
        pgnutls_dh_params_cpy gnutls_dh_params_cpy;
        pgnutls_system_recv_timeout gnutls_system_recv_timeout;
        pgnutls_transport_set_int2 gnutls_transport_set_int2;
        pgnutls_transport_get_int2 gnutls_transport_get_int2;
        pgnutls_transport_get_int gnutls_transport_get_int;
        pgnutls_transport_set_ptr gnutls_transport_set_ptr;
        pgnutls_transport_set_ptr2 gnutls_transport_set_ptr2;
        pgnutls_transport_get_ptr gnutls_transport_get_ptr;
        pgnutls_transport_get_ptr2 gnutls_transport_get_ptr2;
        pgnutls_transport_set_vec_push_function gnutls_transport_set_vec_push_function;
        pgnutls_transport_set_push_function gnutls_transport_set_push_function;
        pgnutls_transport_set_pull_function gnutls_transport_set_pull_function;
        pgnutls_transport_set_pull_timeout_function gnutls_transport_set_pull_timeout_function;
        pgnutls_transport_set_errno_function gnutls_transport_set_errno_function;
        pgnutls_transport_set_errno gnutls_transport_set_errno;
        pgnutls_session_set_ptr gnutls_session_set_ptr;
        pgnutls_session_get_ptr gnutls_session_get_ptr;
        pgnutls_openpgp_send_cert gnutls_openpgp_send_cert;
        pgnutls_fingerprint gnutls_fingerprint;
        pgnutls_random_art gnutls_random_art;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_9)
        {
            pgnutls_idna_map gnutls_idna_map;
            pgnutls_idna_reverse_map gnutls_idna_reverse_map;
        }

        pgnutls_srp_free_client_credentials gnutls_srp_free_client_credentials;
        pgnutls_srp_allocate_client_credentials gnutls_srp_allocate_client_credentials;
        pgnutls_srp_set_client_credentials gnutls_srp_set_client_credentials;
        pgnutls_srp_free_server_credentials gnutls_srp_free_server_credentials;
        pgnutls_srp_allocate_server_credentials gnutls_srp_allocate_server_credentials;
        pgnutls_srp_set_server_credentials_file gnutls_srp_set_server_credentials_file;
        pgnutls_srp_server_get_username gnutls_srp_server_get_username;
        pgnutls_srp_set_prime_bits gnutls_srp_set_prime_bits;
        pgnutls_srp_verifier gnutls_srp_verifier;
        pgnutls_srp_set_server_credentials_function gnutls_srp_set_server_credentials_function;
        pgnutls_srp_set_client_credentials_function gnutls_srp_set_client_credentials_function;
        pgnutls_srp_base64_encode gnutls_srp_base64_encode;
        pgnutls_srp_base64_encode2 gnutls_srp_base64_encode2;
        pgnutls_srp_base64_decode gnutls_srp_base64_decode;
        pgnutls_srp_base64_decode2 gnutls_srp_base64_decode2;
        pgnutls_srp_set_server_fake_salt_seed gnutls_srp_set_server_fake_salt_seed;
        pgnutls_psk_free_client_credentials gnutls_psk_free_client_credentials;
        pgnutls_psk_allocate_client_credentials gnutls_psk_allocate_client_credentials;
        pgnutls_psk_set_client_credentials gnutls_psk_set_client_credentials;
        pgnutls_psk_free_server_credentials gnutls_psk_free_server_credentials;
        pgnutls_psk_allocate_server_credentials gnutls_psk_allocate_server_credentials;
        pgnutls_psk_set_server_credentials_file gnutls_psk_set_server_credentials_file;
        pgnutls_psk_set_server_credentials_hint gnutls_psk_set_server_credentials_hint;
        pgnutls_psk_server_get_username gnutls_psk_server_get_username;
        pgnutls_psk_client_get_hint gnutls_psk_client_get_hint;
        pgnutls_psk_set_server_credentials_function gnutls_psk_set_server_credentials_function;
        pgnutls_psk_set_client_credentials_function gnutls_psk_set_client_credentials_function;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            pgnutls_psk_set_client_credentials2 gnutls_psk_set_client_credentials2;
            pgnutls_psk_server_get_username2 gnutls_psk_server_get_username2;
            pgnutls_psk_set_server_credentials_function2 gnutls_psk_set_server_credentials_function2;
            pgnutls_psk_set_client_credentials_function2 gnutls_psk_set_client_credentials_function2;
        }

        pgnutls_hex_encode gnutls_hex_encode;
        pgnutls_hex_decode gnutls_hex_decode;
        pgnutls_hex_encode2 gnutls_hex_encode2;
        pgnutls_hex_decode2 gnutls_hex_decode2;
        pgnutls_psk_set_server_dh_params gnutls_psk_set_server_dh_params;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            pgnutls_psk_set_server_known_dh_params gnutls_psk_set_server_known_dh_params;

        pgnutls_psk_set_server_params_function gnutls_psk_set_server_params_function;
        pgnutls_auth_get_type gnutls_auth_get_type;
        pgnutls_auth_server_get_type gnutls_auth_server_get_type;
        pgnutls_auth_client_get_type gnutls_auth_client_get_type;
        pgnutls_dh_set_prime_bits gnutls_dh_set_prime_bits;
        pgnutls_dh_get_secret_bits gnutls_dh_get_secret_bits;
        pgnutls_dh_get_peers_public_bits gnutls_dh_get_peers_public_bits;
        pgnutls_dh_get_prime_bits gnutls_dh_get_prime_bits;
        pgnutls_dh_get_group gnutls_dh_get_group;
        pgnutls_dh_get_pubkey gnutls_dh_get_pubkey;
        pgnutls_certificate_set_retrieve_function gnutls_certificate_set_retrieve_function;
        pgnutls_certificate_set_verify_function gnutls_certificate_set_verify_function;
        pgnutls_certificate_server_set_request gnutls_certificate_server_set_request;
        pgnutls_certificate_get_peers gnutls_certificate_get_peers;
        pgnutls_certificate_get_ours gnutls_certificate_get_ours;
        pgnutls_certificate_get_peers_subkey_id gnutls_certificate_get_peers_subkey_id;
        pgnutls_certificate_activation_time_peers gnutls_certificate_activation_time_peers;
        pgnutls_certificate_expiration_time_peers gnutls_certificate_expiration_time_peers;
        pgnutls_certificate_client_get_request_status gnutls_certificate_client_get_request_status;
        pgnutls_certificate_verify_peers2 gnutls_certificate_verify_peers2;
        pgnutls_certificate_verify_peers3 gnutls_certificate_verify_peers3;
        pgnutls_certificate_verify_peers gnutls_certificate_verify_peers;
        pgnutls_certificate_verification_status_print gnutls_certificate_verification_status_print;
        pgnutls_pem_base64_encode gnutls_pem_base64_encode;
        pgnutls_pem_base64_decode gnutls_pem_base64_decode;
        pgnutls_pem_base64_encode2 gnutls_pem_base64_encode2;
        pgnutls_pem_base64_decode2 gnutls_pem_base64_decode2;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            pgnutls_base64_encode2 gnutls_base64_encode2;
            pgnutls_base64_decode2 gnutls_base64_decode2;
        }

        pgnutls_certificate_set_params_function gnutls_certificate_set_params_function;
        pgnutls_anon_set_params_function gnutls_anon_set_params_function;
        pgnutls_psk_set_params_function gnutls_psk_set_params_function;
        pgnutls_hex2bin gnutls_hex2bin;
        pgnutls_tdb_init gnutls_tdb_init;
        pgnutls_tdb_set_store_func gnutls_tdb_set_store_func;
        pgnutls_tdb_set_store_commitment_func gnutls_tdb_set_store_commitment_func;
        pgnutls_tdb_set_verify_func gnutls_tdb_set_verify_func;
        pgnutls_tdb_deinit gnutls_tdb_deinit;
        pgnutls_verify_stored_pubkey gnutls_verify_stored_pubkey;
        pgnutls_store_commitment gnutls_store_commitment;
        pgnutls_store_pubkey gnutls_store_pubkey;
        pgnutls_load_file gnutls_load_file;
        pgnutls_url_is_supported gnutls_url_is_supported;
        pgnutls_certificate_set_pin_function gnutls_certificate_set_pin_function;
        pgnutls_buffer_append_data gnutls_buffer_append_data;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            pgnutls_utf8_password_normalize gnutls_utf8_password_normalize;

        pgnutls_ext_set_data gnutls_ext_set_data;
        pgnutls_ext_get_data gnutls_ext_get_data;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            pgnutls_ext_get_current_msg gnutls_ext_get_current_msg;
            pgnutls_ext_raw_parse gnutls_ext_raw_parse;
        }

        pgnutls_ext_register gnutls_ext_register;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            pgnutls_session_ext_register gnutls_session_ext_register;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            pgnutls_ext_get_name gnutls_ext_get_name;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_14)
            pgnutls_ext_get_name2 gnutls_ext_get_name2;

        pgnutls_supplemental_register gnutls_supplemental_register;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            pgnutls_session_supplemental_register gnutls_session_supplemental_register;

        pgnutls_supplemental_recv gnutls_supplemental_recv;
        pgnutls_supplemental_send gnutls_supplemental_send;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            pgnutls_anti_replay_init gnutls_anti_replay_init;
            pgnutls_anti_replay_deinit gnutls_anti_replay_deinit;
            pgnutls_anti_replay_set_window gnutls_anti_replay_set_window;
            pgnutls_anti_replay_enable gnutls_anti_replay_enable;
            pgnutls_anti_replay_set_add_function gnutls_anti_replay_set_add_function;
        }

        pgnutls_anti_replay_set_ptr gnutls_anti_replay_set_ptr;
        pgnutls_fips140_mode_enabled gnutls_fips140_mode_enabled;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_fips140_set_mode gnutls_fips140_set_mode;
    }

    import bindbc.loader : SharedLib, bindSymbol, bindSymbol_stdcall;
    void bindGnutls(SharedLib lib)
    {
        // global symbols
        lib.bindSymbol_stdcall(gnutls_malloc_, "gnutls_malloc");
        lib.bindSymbol_stdcall(gnutls_realloc_, "gnutls_realloc");
        lib.bindSymbol_stdcall(gnutls_calloc_, "gnutls_calloc");
        lib.bindSymbol_stdcall(gnutls_free_, "gnutls_free");
        lib.bindSymbol_stdcall(gnutls_strdup_, "gnutls_strdup");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_2)
        {
            lib.bindSymbol_stdcall(gnutls_srp_8192_group_prime_, "gnutls_srp_8192_group_prime");
            lib.bindSymbol_stdcall(gnutls_srp_8192_group_generator_, "gnutls_srp_8192_group_generator");
        }

        lib.bindSymbol_stdcall(gnutls_srp_4096_group_prime_, "gnutls_srp_4096_group_prime");
        lib.bindSymbol_stdcall(gnutls_srp_4096_group_generator_, "gnutls_srp_4096_group_generator");
        lib.bindSymbol_stdcall(gnutls_srp_3072_group_prime_, "gnutls_srp_3072_group_prime");
        lib.bindSymbol_stdcall(gnutls_srp_3072_group_generator_, "gnutls_srp_3072_group_generator");
        lib.bindSymbol_stdcall(gnutls_srp_2048_group_prime_, "gnutls_srp_2048_group_prime");
        lib.bindSymbol_stdcall(gnutls_srp_2048_group_generator_, "gnutls_srp_2048_group_generator");
        lib.bindSymbol_stdcall(gnutls_srp_1536_group_prime_, "gnutls_srp_1536_group_prime");
        lib.bindSymbol_stdcall(gnutls_srp_1536_group_generator_, "gnutls_srp_1536_group_generator");
        lib.bindSymbol_stdcall(gnutls_srp_1024_group_prime_, "gnutls_srp_1024_group_prime");
        lib.bindSymbol_stdcall(gnutls_srp_1024_group_generator_, "gnutls_srp_1024_group_generator");
        lib.bindSymbol_stdcall(gnutls_ffdhe_8192_group_prime_, "gnutls_ffdhe_8192_group_prime");
        lib.bindSymbol_stdcall(gnutls_ffdhe_8192_group_generator_, "gnutls_ffdhe_8192_group_generator");
        lib.bindSymbol_stdcall(gnutls_ffdhe_8192_key_bits_, "gnutls_ffdhe_8192_key_bits");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
        {
            lib.bindSymbol_stdcall(gnutls_ffdhe_6144_group_prime_, "gnutls_ffdhe_6144_group_prime");
            lib.bindSymbol_stdcall(gnutls_ffdhe_6144_group_generator_, "gnutls_ffdhe_6144_group_generator");
            lib.bindSymbol_stdcall(gnutls_ffdhe_6144_key_bits_, "gnutls_ffdhe_6144_key_bits");
        }

        lib.bindSymbol_stdcall(gnutls_ffdhe_4096_group_prime_, "gnutls_ffdhe_4096_group_prime");
        lib.bindSymbol_stdcall(gnutls_ffdhe_4096_group_generator_, "gnutls_ffdhe_4096_group_generator");
        lib.bindSymbol_stdcall(gnutls_ffdhe_4096_key_bits_, "gnutls_ffdhe_4096_key_bits");
        lib.bindSymbol_stdcall(gnutls_ffdhe_3072_group_prime_, "gnutls_ffdhe_3072_group_prime");
        lib.bindSymbol_stdcall(gnutls_ffdhe_3072_group_generator_, "gnutls_ffdhe_3072_group_generator");
        lib.bindSymbol_stdcall(gnutls_ffdhe_3072_key_bits_, "gnutls_ffdhe_3072_key_bits");
        lib.bindSymbol_stdcall(gnutls_ffdhe_2048_group_prime_, "gnutls_ffdhe_2048_group_prime");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
        {
            lib.bindSymbol_stdcall(gnutls_ffdhe_2048_group_q_, "gnutls_ffdhe_2048_group_q");
            lib.bindSymbol_stdcall(gnutls_ffdhe_3072_group_q_, "gnutls_ffdhe_3072_group_q");
            lib.bindSymbol_stdcall(gnutls_ffdhe_4096_group_q_, "gnutls_ffdhe_4096_group_q");
            lib.bindSymbol_stdcall(gnutls_ffdhe_6144_group_q_, "gnutls_ffdhe_6144_group_q");
            lib.bindSymbol_stdcall(gnutls_ffdhe_8192_group_q_, "gnutls_ffdhe_8192_group_q");
        }

        lib.bindSymbol_stdcall(gnutls_ffdhe_2048_group_generator_, "gnutls_ffdhe_2048_group_generator");
        lib.bindSymbol_stdcall(gnutls_ffdhe_2048_key_bits_, "gnutls_ffdhe_2048_key_bits");

        // functions
        lib.bindSymbol_stdcall(gnutls_pk_algorithm_get_name, "gnutls_pk_algorithm_get_name");
        lib.bindSymbol_stdcall(gnutls_init, "gnutls_init");
        lib.bindSymbol_stdcall(gnutls_deinit, "gnutls_deinit");
        lib.bindSymbol_stdcall(gnutls_bye, "gnutls_bye");
        lib.bindSymbol_stdcall(gnutls_handshake, "gnutls_handshake");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_reauth, "gnutls_reauth");

        lib.bindSymbol_stdcall(gnutls_handshake_set_timeout, "gnutls_handshake_set_timeout");
        lib.bindSymbol_stdcall(gnutls_rehandshake, "gnutls_rehandshake");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_session_key_update, "gnutls_session_key_update");

        lib.bindSymbol_stdcall(gnutls_alert_get, "gnutls_alert_get");
        lib.bindSymbol_stdcall(gnutls_alert_send, "gnutls_alert_send");
        lib.bindSymbol_stdcall(gnutls_alert_send_appropriate, "gnutls_alert_send_appropriate");
        lib.bindSymbol_stdcall(gnutls_alert_get_name, "gnutls_alert_get_name");
        lib.bindSymbol_stdcall(gnutls_alert_get_strname, "gnutls_alert_get_strname");
        lib.bindSymbol_stdcall(gnutls_pk_bits_to_sec_param, "gnutls_pk_bits_to_sec_param");
        lib.bindSymbol_stdcall(gnutls_sec_param_get_name, "gnutls_sec_param_get_name");
        lib.bindSymbol_stdcall(gnutls_sec_param_to_pk_bits, "gnutls_sec_param_to_pk_bits");
        lib.bindSymbol_stdcall(gnutls_sec_param_to_symmetric_bits, "gnutls_sec_param_to_symmetric_bits");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get_name, "gnutls_ecc_curve_get_name");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get_oid, "gnutls_ecc_curve_get_oid");
        lib.bindSymbol_stdcall(gnutls_group_get_name, "gnutls_group_get_name");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get_size, "gnutls_ecc_curve_get_size");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get, "gnutls_ecc_curve_get");
        lib.bindSymbol_stdcall(gnutls_group_get, "gnutls_group_get");
        lib.bindSymbol_stdcall(gnutls_cipher_get, "gnutls_cipher_get");
        lib.bindSymbol_stdcall(gnutls_kx_get, "gnutls_kx_get");
        lib.bindSymbol_stdcall(gnutls_mac_get, "gnutls_mac_get");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
            lib.bindSymbol_stdcall(gnutls_prf_hash_get, "gnutls_prf_hash_get");

        lib.bindSymbol_stdcall(gnutls_certificate_type_get, "gnutls_certificate_type_get");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            lib.bindSymbol_stdcall(gnutls_certificate_type_get2, "gnutls_certificate_type_get2");

        lib.bindSymbol_stdcall(gnutls_sign_algorithm_get, "gnutls_sign_algorithm_get");
        lib.bindSymbol_stdcall(gnutls_sign_algorithm_get_client, "gnutls_sign_algorithm_get_client");
        lib.bindSymbol_stdcall(gnutls_sign_algorithm_get_requested, "gnutls_sign_algorithm_get_requested");
        lib.bindSymbol_stdcall(gnutls_cipher_get_name, "gnutls_cipher_get_name");
        lib.bindSymbol_stdcall(gnutls_mac_get_name, "gnutls_mac_get_name");
        lib.bindSymbol_stdcall(gnutls_digest_get_name, "gnutls_digest_get_name");
        lib.bindSymbol_stdcall(gnutls_digest_get_oid, "gnutls_digest_get_oid");
        lib.bindSymbol_stdcall(gnutls_kx_get_name, "gnutls_kx_get_name");
        lib.bindSymbol_stdcall(gnutls_certificate_type_get_name, "gnutls_certificate_type_get_name");
        lib.bindSymbol_stdcall(gnutls_pk_get_name, "gnutls_pk_get_name");
        lib.bindSymbol_stdcall(gnutls_pk_get_oid, "gnutls_pk_get_oid");
        lib.bindSymbol_stdcall(gnutls_sign_get_name, "gnutls_sign_get_name");
        lib.bindSymbol_stdcall(gnutls_sign_get_oid, "gnutls_sign_get_oid");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            lib.bindSymbol_stdcall(gnutls_gost_paramset_get_name, "gnutls_gost_paramset_get_name");
            lib.bindSymbol_stdcall(gnutls_gost_paramset_get_oid, "gnutls_gost_paramset_get_oid");
        }

        lib.bindSymbol_stdcall(gnutls_cipher_get_key_size, "gnutls_cipher_get_key_size");
        lib.bindSymbol_stdcall(gnutls_mac_get_key_size, "gnutls_mac_get_key_size");
        lib.bindSymbol_stdcall(gnutls_sign_is_secure, "gnutls_sign_is_secure");
        lib.bindSymbol_stdcall(gnutls_sign_is_secure2, "gnutls_sign_is_secure2");
        lib.bindSymbol_stdcall(gnutls_sign_get_hash_algorithm, "gnutls_sign_get_hash_algorithm");
        lib.bindSymbol_stdcall(gnutls_sign_get_pk_algorithm, "gnutls_sign_get_pk_algorithm");
        lib.bindSymbol_stdcall(gnutls_pk_to_sign, "gnutls_pk_to_sign");
        lib.bindSymbol_stdcall(gnutls_sign_supports_pk_algorithm, "gnutls_sign_supports_pk_algorithm");
        lib.bindSymbol_stdcall(gnutls_mac_get_id, "gnutls_mac_get_id");
        lib.bindSymbol_stdcall(gnutls_digest_get_id, "gnutls_digest_get_id");
        lib.bindSymbol_stdcall(gnutls_cipher_get_id, "gnutls_cipher_get_id");
        lib.bindSymbol_stdcall(gnutls_kx_get_id, "gnutls_kx_get_id");
        lib.bindSymbol_stdcall(gnutls_protocol_get_id, "gnutls_protocol_get_id");
        lib.bindSymbol_stdcall(gnutls_certificate_type_get_id, "gnutls_certificate_type_get_id");
        lib.bindSymbol_stdcall(gnutls_pk_get_id, "gnutls_pk_get_id");
        lib.bindSymbol_stdcall(gnutls_sign_get_id, "gnutls_sign_get_id");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get_id, "gnutls_ecc_curve_get_id");
        lib.bindSymbol_stdcall(gnutls_ecc_curve_get_pk, "gnutls_ecc_curve_get_pk");
        lib.bindSymbol_stdcall(gnutls_group_get_id, "gnutls_group_get_id");
        lib.bindSymbol_stdcall(gnutls_oid_to_digest, "gnutls_oid_to_digest");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_4)
            lib.bindSymbol_stdcall(gnutls_oid_to_mac, "gnutls_oid_to_mac");

        lib.bindSymbol_stdcall(gnutls_oid_to_pk, "gnutls_oid_to_pk");
        lib.bindSymbol_stdcall(gnutls_oid_to_sign, "gnutls_oid_to_sign");
        lib.bindSymbol_stdcall(gnutls_oid_to_ecc_curve, "gnutls_oid_to_ecc_curve");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_oid_to_gost_paramset, "gnutls_oid_to_gost_paramset");

        lib.bindSymbol_stdcall(gnutls_ecc_curve_list, "gnutls_ecc_curve_list");
        lib.bindSymbol_stdcall(gnutls_group_list, "gnutls_group_list");
        lib.bindSymbol_stdcall(gnutls_cipher_list, "gnutls_cipher_list");
        lib.bindSymbol_stdcall(gnutls_mac_list, "gnutls_mac_list");
        lib.bindSymbol_stdcall(gnutls_digest_list, "gnutls_digest_list");
        lib.bindSymbol_stdcall(gnutls_protocol_list, "gnutls_protocol_list");
        lib.bindSymbol_stdcall(gnutls_certificate_type_list, "gnutls_certificate_type_list");
        lib.bindSymbol_stdcall(gnutls_kx_list, "gnutls_kx_list");
        lib.bindSymbol_stdcall(gnutls_pk_list, "gnutls_pk_list");
        lib.bindSymbol_stdcall(gnutls_sign_list, "gnutls_sign_list");
        lib.bindSymbol_stdcall(gnutls_cipher_suite_info, "gnutls_cipher_suite_info");
        lib.bindSymbol_stdcall(gnutls_error_is_fatal, "gnutls_error_is_fatal");
        lib.bindSymbol_stdcall(gnutls_error_to_alert, "gnutls_error_to_alert");
        lib.bindSymbol_stdcall(gnutls_perror, "gnutls_perror");
        lib.bindSymbol_stdcall(gnutls_strerror, "gnutls_strerror");
        lib.bindSymbol_stdcall(gnutls_strerror_name, "gnutls_strerror_name");
        lib.bindSymbol_stdcall(gnutls_handshake_set_private_extensions, "gnutls_handshake_set_private_extensions");
        lib.bindSymbol_stdcall(gnutls_handshake_set_random, "gnutls_handshake_set_random");
        lib.bindSymbol_stdcall(gnutls_handshake_get_last_out, "gnutls_handshake_get_last_out");
        lib.bindSymbol_stdcall(gnutls_handshake_get_last_in, "gnutls_handshake_get_last_in");
        lib.bindSymbol_stdcall(gnutls_heartbeat_ping, "gnutls_heartbeat_ping");
        lib.bindSymbol_stdcall(gnutls_heartbeat_pong, "gnutls_heartbeat_pong");
        lib.bindSymbol_stdcall(gnutls_record_set_timeout, "gnutls_record_set_timeout");
        lib.bindSymbol_stdcall(gnutls_record_disable_padding, "gnutls_record_disable_padding");
        lib.bindSymbol_stdcall(gnutls_record_cork, "gnutls_record_cork");
        lib.bindSymbol_stdcall(gnutls_record_uncork, "gnutls_record_uncork");
        lib.bindSymbol_stdcall(gnutls_record_discard_queued, "gnutls_record_discard_queued");
        lib.bindSymbol_stdcall(gnutls_record_get_state, "gnutls_record_get_state");
        lib.bindSymbol_stdcall(gnutls_record_set_state, "gnutls_record_set_state");
        lib.bindSymbol_stdcall(gnutls_range_split, "gnutls_range_split");
        lib.bindSymbol_stdcall(gnutls_record_send, "gnutls_record_send");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_record_send2, "gnutls_record_send2");

        lib.bindSymbol_stdcall(gnutls_record_send_range, "gnutls_record_send_range");
        lib.bindSymbol_stdcall(gnutls_record_recv, "gnutls_record_recv");
        lib.bindSymbol_stdcall(gnutls_record_recv_packet, "gnutls_record_recv_packet");
        lib.bindSymbol_stdcall(gnutls_packet_get, "gnutls_packet_get");
        lib.bindSymbol_stdcall(gnutls_packet_deinit, "gnutls_packet_deinit");
        lib.bindSymbol_stdcall(gnutls_record_recv_seq, "gnutls_record_recv_seq");
        lib.bindSymbol_stdcall(gnutls_record_overhead_size, "gnutls_record_overhead_size");
        lib.bindSymbol_stdcall(gnutls_est_record_overhead_size, "gnutls_est_record_overhead_size");
        lib.bindSymbol_stdcall(gnutls_session_enable_compatibility_mode, "gnutls_session_enable_compatibility_mode");
        lib.bindSymbol_stdcall(gnutls_record_can_use_length_hiding, "gnutls_record_can_use_length_hiding");
        lib.bindSymbol_stdcall(gnutls_record_get_direction, "gnutls_record_get_direction");
        lib.bindSymbol_stdcall(gnutls_record_get_max_size, "gnutls_record_get_max_size");
        lib.bindSymbol_stdcall(gnutls_record_set_max_size, "gnutls_record_set_max_size");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            lib.bindSymbol_stdcall(gnutls_record_set_max_recv_size, "gnutls_record_set_max_recv_size");

        lib.bindSymbol_stdcall(gnutls_record_check_pending, "gnutls_record_check_pending");
        lib.bindSymbol_stdcall(gnutls_record_check_corked, "gnutls_record_check_corked");


        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            lib.bindSymbol_stdcall(gnutls_record_set_max_early_data_size, "gnutls_record_set_max_early_data_size");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            lib.bindSymbol_stdcall(gnutls_record_get_max_early_data_size, "gnutls_record_get_max_early_data_size");
            lib.bindSymbol_stdcall(gnutls_record_send_early_data, "gnutls_record_send_early_data");
            lib.bindSymbol_stdcall(gnutls_record_recv_early_data, "gnutls_record_recv_early_data");
        }

        lib.bindSymbol_stdcall(gnutls_session_force_valid, "gnutls_session_force_valid");
        lib.bindSymbol_stdcall(gnutls_prf, "gnutls_prf");
        lib.bindSymbol_stdcall(gnutls_prf_rfc5705, "gnutls_prf_rfc5705");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            lib.bindSymbol_stdcall(gnutls_prf_early, "gnutls_prf_early");

        lib.bindSymbol_stdcall(gnutls_prf_raw, "gnutls_prf_raw");
        lib.bindSymbol_stdcall(gnutls_server_name_set, "gnutls_server_name_set");
        lib.bindSymbol_stdcall(gnutls_server_name_get, "gnutls_server_name_get");
        lib.bindSymbol_stdcall(gnutls_heartbeat_get_timeout, "gnutls_heartbeat_get_timeout");
        lib.bindSymbol_stdcall(gnutls_heartbeat_set_timeouts, "gnutls_heartbeat_set_timeouts");
        lib.bindSymbol_stdcall(gnutls_heartbeat_enable, "gnutls_heartbeat_enable");
        lib.bindSymbol_stdcall(gnutls_heartbeat_allowed, "gnutls_heartbeat_allowed");
        lib.bindSymbol_stdcall(gnutls_safe_renegotiation_status, "gnutls_safe_renegotiation_status");
        lib.bindSymbol_stdcall(gnutls_session_ext_master_secret_status, "gnutls_session_ext_master_secret_status");
        lib.bindSymbol_stdcall(gnutls_session_etm_status, "gnutls_session_etm_status");
        lib.bindSymbol_stdcall(gnutls_session_get_flags, "gnutls_session_get_flags");
        lib.bindSymbol_stdcall(gnutls_supplemental_get_name, "gnutls_supplemental_get_name");
        lib.bindSymbol_stdcall(gnutls_session_ticket_key_generate, "gnutls_session_ticket_key_generate");
        lib.bindSymbol_stdcall(gnutls_session_ticket_enable_client, "gnutls_session_ticket_enable_client");
        lib.bindSymbol_stdcall(gnutls_session_ticket_enable_server, "gnutls_session_ticket_enable_server");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_session_ticket_send, "gnutls_session_ticket_send");

        lib.bindSymbol_stdcall(gnutls_srtp_set_profile, "gnutls_srtp_set_profile");
        lib.bindSymbol_stdcall(gnutls_srtp_set_profile_direct, "gnutls_srtp_set_profile_direct");
        lib.bindSymbol_stdcall(gnutls_srtp_get_selected_profile, "gnutls_srtp_get_selected_profile");
        lib.bindSymbol_stdcall(gnutls_srtp_get_profile_name, "gnutls_srtp_get_profile_name");
        lib.bindSymbol_stdcall(gnutls_srtp_get_profile_id, "gnutls_srtp_get_profile_id");
        lib.bindSymbol_stdcall(gnutls_srtp_get_keys, "gnutls_srtp_get_keys");
        lib.bindSymbol_stdcall(gnutls_srtp_set_mki, "gnutls_srtp_set_mki");
        lib.bindSymbol_stdcall(gnutls_srtp_get_mki, "gnutls_srtp_get_mki");
        lib.bindSymbol_stdcall(gnutls_alpn_get_selected_protocol, "gnutls_alpn_get_selected_protocol");
        lib.bindSymbol_stdcall(gnutls_alpn_set_protocols, "gnutls_alpn_set_protocols");
        lib.bindSymbol_stdcall(gnutls_key_generate, "gnutls_key_generate");
        lib.bindSymbol_stdcall(gnutls_priority_init, "gnutls_priority_init");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_priority_init2, "gnutls_priority_init2");

        lib.bindSymbol_stdcall(gnutls_priority_deinit, "gnutls_priority_deinit");
        lib.bindSymbol_stdcall(gnutls_priority_get_cipher_suite_index, "gnutls_priority_get_cipher_suite_index");
        lib.bindSymbol_stdcall(gnutls_priority_string_list, "gnutls_priority_string_list");
        lib.bindSymbol_stdcall(gnutls_priority_set, "gnutls_priority_set");
        lib.bindSymbol_stdcall(gnutls_priority_set_direct, "gnutls_priority_set_direct");
        lib.bindSymbol_stdcall(gnutls_priority_certificate_type_list, "gnutls_priority_certificate_type_list");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_4)
            lib.bindSymbol_stdcall(gnutls_priority_certificate_type_list2, "gnutls_priority_certificate_type_list2");

        lib.bindSymbol_stdcall(gnutls_priority_sign_list, "gnutls_priority_sign_list");
        lib.bindSymbol_stdcall(gnutls_priority_protocol_list, "gnutls_priority_protocol_list");
        lib.bindSymbol_stdcall(gnutls_priority_ecc_curve_list, "gnutls_priority_ecc_curve_list");
        lib.bindSymbol_stdcall(gnutls_priority_group_list, "gnutls_priority_group_list");
        lib.bindSymbol_stdcall(gnutls_priority_kx_list, "gnutls_priority_kx_list");
        lib.bindSymbol_stdcall(gnutls_priority_cipher_list, "gnutls_priority_cipher_list");
        lib.bindSymbol_stdcall(gnutls_priority_mac_list, "gnutls_priority_mac_list");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            lib.bindSymbol_stdcall(gnutls_get_system_config_file, "gnutls_get_system_config_file");

        lib.bindSymbol_stdcall(gnutls_set_default_priority, "gnutls_set_default_priority");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_set_default_priority_append, "gnutls_set_default_priority_append");

        lib.bindSymbol_stdcall(gnutls_cipher_suite_get_name, "gnutls_cipher_suite_get_name");
        lib.bindSymbol_stdcall(gnutls_protocol_get_version, "gnutls_protocol_get_version");
        lib.bindSymbol_stdcall(gnutls_protocol_get_name, "gnutls_protocol_get_name");
        lib.bindSymbol_stdcall(gnutls_session_set_data, "gnutls_session_set_data");
        lib.bindSymbol_stdcall(gnutls_session_get_data, "gnutls_session_get_data");
        lib.bindSymbol_stdcall(gnutls_session_get_data2, "gnutls_session_get_data2");
        lib.bindSymbol_stdcall(gnutls_session_get_random, "gnutls_session_get_random");
        lib.bindSymbol_stdcall(gnutls_session_get_master_secret, "gnutls_session_get_master_secret");
        lib.bindSymbol_stdcall(gnutls_session_get_desc, "gnutls_session_get_desc");
        lib.bindSymbol_stdcall(gnutls_session_set_verify_function, "gnutls_session_set_verify_function");
        lib.bindSymbol_stdcall(gnutls_session_set_verify_cert, "gnutls_session_set_verify_cert");
        lib.bindSymbol_stdcall(gnutls_session_set_verify_cert2, "gnutls_session_set_verify_cert2");
        lib.bindSymbol_stdcall(gnutls_session_get_verify_cert_status, "gnutls_session_get_verify_cert_status");
        lib.bindSymbol_stdcall(gnutls_session_set_premaster, "gnutls_session_set_premaster");
        lib.bindSymbol_stdcall(gnutls_session_get_id, "gnutls_session_get_id");
        lib.bindSymbol_stdcall(gnutls_session_get_id2, "gnutls_session_get_id2");
        lib.bindSymbol_stdcall(gnutls_session_set_id, "gnutls_session_set_id");
        lib.bindSymbol_stdcall(gnutls_session_channel_binding, "gnutls_session_channel_binding");
        lib.bindSymbol_stdcall(gnutls_session_is_resumed, "gnutls_session_is_resumed");
        lib.bindSymbol_stdcall(gnutls_session_resumption_requested, "gnutls_session_resumption_requested");
        lib.bindSymbol_stdcall(gnutls_db_set_cache_expiration, "gnutls_db_set_cache_expiration");
        lib.bindSymbol_stdcall(gnutls_db_get_default_cache_expiration, "gnutls_db_get_default_cache_expiration");
        lib.bindSymbol_stdcall(gnutls_db_remove_session, "gnutls_db_remove_session");
        lib.bindSymbol_stdcall(gnutls_db_set_retrieve_function, "gnutls_db_set_retrieve_function");
        lib.bindSymbol_stdcall(gnutls_db_set_remove_function, "gnutls_db_set_remove_function");
        lib.bindSymbol_stdcall(gnutls_db_set_store_function, "gnutls_db_set_store_function");
        lib.bindSymbol_stdcall(gnutls_db_set_ptr, "gnutls_db_set_ptr");
        lib.bindSymbol_stdcall(gnutls_db_get_ptr, "gnutls_db_get_ptr");
        lib.bindSymbol_stdcall(gnutls_db_check_entry, "gnutls_db_check_entry");
        lib.bindSymbol_stdcall(gnutls_db_check_entry_time, "gnutls_db_check_entry_time");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
            lib.bindSymbol_stdcall(gnutls_db_check_entry_expire_time, "gnutls_db_check_entry_expire_time");

        lib.bindSymbol_stdcall(gnutls_handshake_set_hook_function, "gnutls_handshake_set_hook_function");
        lib.bindSymbol_stdcall(gnutls_handshake_set_post_client_hello_function, "gnutls_handshake_set_post_client_hello_function");
        lib.bindSymbol_stdcall(gnutls_handshake_set_max_packet_length, "gnutls_handshake_set_max_packet_length");
        lib.bindSymbol_stdcall(gnutls_check_version, "gnutls_check_version");
        lib.bindSymbol_stdcall(gnutls_credentials_clear, "gnutls_credentials_clear");
        lib.bindSymbol_stdcall(gnutls_credentials_set, "gnutls_credentials_set");
        lib.bindSymbol_stdcall(gnutls_credentials_get, "gnutls_credentials_get");
        lib.bindSymbol_stdcall(gnutls_anon_free_server_credentials, "gnutls_anon_free_server_credentials");
        lib.bindSymbol_stdcall(gnutls_anon_allocate_server_credentials, "gnutls_anon_allocate_server_credentials");
        lib.bindSymbol_stdcall(gnutls_anon_set_server_dh_params, "gnutls_anon_set_server_dh_params");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            lib.bindSymbol_stdcall(gnutls_anon_set_server_known_dh_params, "gnutls_anon_set_server_known_dh_params");

        lib.bindSymbol_stdcall(gnutls_anon_set_server_params_function, "gnutls_anon_set_server_params_function");
        lib.bindSymbol_stdcall(gnutls_anon_free_client_credentials, "gnutls_anon_free_client_credentials");
        lib.bindSymbol_stdcall(gnutls_anon_allocate_client_credentials, "gnutls_anon_allocate_client_credentials");
        lib.bindSymbol_stdcall(gnutls_certificate_free_credentials, "gnutls_certificate_free_credentials");
        lib.bindSymbol_stdcall(gnutls_certificate_allocate_credentials, "gnutls_certificate_allocate_credentials");
        lib.bindSymbol_stdcall(gnutls_certificate_get_issuer, "gnutls_certificate_get_issuer");
        lib.bindSymbol_stdcall(gnutls_certificate_get_crt_raw, "gnutls_certificate_get_crt_raw");
        lib.bindSymbol_stdcall(gnutls_certificate_free_keys, "gnutls_certificate_free_keys");
        lib.bindSymbol_stdcall(gnutls_certificate_free_cas, "gnutls_certificate_free_cas");
        lib.bindSymbol_stdcall(gnutls_certificate_free_ca_names, "gnutls_certificate_free_ca_names");
        lib.bindSymbol_stdcall(gnutls_certificate_free_crls, "gnutls_certificate_free_crls");
        lib.bindSymbol_stdcall(gnutls_certificate_set_dh_params, "gnutls_certificate_set_dh_params");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            lib.bindSymbol_stdcall(gnutls_certificate_set_known_dh_params, "gnutls_certificate_set_known_dh_params");

        lib.bindSymbol_stdcall(gnutls_certificate_set_verify_flags, "gnutls_certificate_set_verify_flags");
        lib.bindSymbol_stdcall(gnutls_certificate_get_verify_flags, "gnutls_certificate_get_verify_flags");
        lib.bindSymbol_stdcall(gnutls_certificate_set_flags, "gnutls_certificate_set_flags");
        lib.bindSymbol_stdcall(gnutls_certificate_set_verify_limits, "gnutls_certificate_set_verify_limits");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_system_trust, "gnutls_certificate_set_x509_system_trust");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_trust_file, "gnutls_certificate_set_x509_trust_file");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_trust_dir, "gnutls_certificate_set_x509_trust_dir");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_trust_mem, "gnutls_certificate_set_x509_trust_mem");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_crl_file, "gnutls_certificate_set_x509_crl_file");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_crl_mem, "gnutls_certificate_set_x509_crl_mem");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_key_file, "gnutls_certificate_set_x509_key_file");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_key_file2, "gnutls_certificate_set_x509_key_file2");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_key_mem, "gnutls_certificate_set_x509_key_mem");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_key_mem2, "gnutls_certificate_set_x509_key_mem2");
        lib.bindSymbol_stdcall(gnutls_certificate_send_x509_rdn_sequence, "gnutls_certificate_send_x509_rdn_sequence");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_simple_pkcs12_file, "gnutls_certificate_set_x509_simple_pkcs12_file");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_simple_pkcs12_mem, "gnutls_certificate_set_x509_simple_pkcs12_mem");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_key, "gnutls_certificate_set_x509_key");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_trust, "gnutls_certificate_set_x509_trust");
        lib.bindSymbol_stdcall(gnutls_certificate_set_x509_crl, "gnutls_certificate_set_x509_crl");
        lib.bindSymbol_stdcall(gnutls_certificate_get_x509_key, "gnutls_certificate_get_x509_key");
        lib.bindSymbol_stdcall(gnutls_certificate_get_x509_crt, "gnutls_certificate_get_x509_crt");
        lib.bindSymbol_stdcall(gnutls_certificate_set_ocsp_status_request_function, "gnutls_certificate_set_ocsp_status_request_function");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            lib.bindSymbol_stdcall(gnutls_certificate_set_ocsp_status_request_function2, "gnutls_certificate_set_ocsp_status_request_function2");

        lib.bindSymbol_stdcall(gnutls_certificate_set_ocsp_status_request_file, "gnutls_certificate_set_ocsp_status_request_file");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            lib.bindSymbol_stdcall(gnutls_certificate_set_ocsp_status_request_file2, "gnutls_certificate_set_ocsp_status_request_file2");
            lib.bindSymbol_stdcall(gnutls_certificate_set_ocsp_status_request_mem, "gnutls_certificate_set_ocsp_status_request_mem");
            lib.bindSymbol_stdcall(gnutls_certificate_get_ocsp_expiration, "gnutls_certificate_get_ocsp_expiration");
        }

        lib.bindSymbol_stdcall(gnutls_ocsp_status_request_enable_client, "gnutls_ocsp_status_request_enable_client");
        lib.bindSymbol_stdcall(gnutls_ocsp_status_request_get, "gnutls_ocsp_status_request_get");
        lib.bindSymbol_stdcall(gnutls_ocsp_status_request_is_checked, "gnutls_ocsp_status_request_is_checked");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_ocsp_status_request_get2, "gnutls_ocsp_status_request_get2");

        lib.bindSymbol_stdcall(gnutls_certificate_set_rawpk_key_mem, "gnutls_certificate_set_rawpk_key_mem");
        lib.bindSymbol_stdcall(gnutls_certificate_set_rawpk_key_file, "gnutls_certificate_set_rawpk_key_file");
        lib.bindSymbol_stdcall(gnutls_global_init, "gnutls_global_init");
        lib.bindSymbol_stdcall(gnutls_global_deinit, "gnutls_global_deinit");
        lib.bindSymbol_stdcall(gnutls_global_set_mutex, "gnutls_global_set_mutex");
        lib.bindSymbol_stdcall(gnutls_global_set_time_function, "gnutls_global_set_time_function");
        lib.bindSymbol_stdcall(gnutls_memset, "gnutls_memset");
        lib.bindSymbol_stdcall(gnutls_memcmp, "gnutls_memcmp");
        lib.bindSymbol_stdcall(gnutls_global_set_log_function, "gnutls_global_set_log_function");
        lib.bindSymbol_stdcall(gnutls_global_set_audit_log_function, "gnutls_global_set_audit_log_function");
        lib.bindSymbol_stdcall(gnutls_global_set_log_level, "gnutls_global_set_log_level");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            lib.bindSymbol_stdcall(gnutls_session_get_keylog_function, "gnutls_session_get_keylog_function");
            lib.bindSymbol_stdcall(gnutls_session_set_keylog_function, "gnutls_session_set_keylog_function");
        }

        lib.bindSymbol_stdcall(gnutls_dh_params_init, "gnutls_dh_params_init");
        lib.bindSymbol_stdcall(gnutls_dh_params_deinit, "gnutls_dh_params_deinit");
        lib.bindSymbol_stdcall(gnutls_dh_params_import_raw, "gnutls_dh_params_import_raw");
        lib.bindSymbol_stdcall(gnutls_dh_params_import_dsa, "gnutls_dh_params_import_dsa");
        lib.bindSymbol_stdcall(gnutls_dh_params_import_raw2, "gnutls_dh_params_import_raw2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_8)
            lib.bindSymbol_stdcall(gnutls_dh_params_import_raw3, "gnutls_dh_params_import_raw3");

        lib.bindSymbol_stdcall(gnutls_dh_params_import_pkcs3, "gnutls_dh_params_import_pkcs3");
        lib.bindSymbol_stdcall(gnutls_dh_params_generate2, "gnutls_dh_params_generate2");
        lib.bindSymbol_stdcall(gnutls_dh_params_export_pkcs3, "gnutls_dh_params_export_pkcs3");
        lib.bindSymbol_stdcall(gnutls_dh_params_export2_pkcs3, "gnutls_dh_params_export2_pkcs3");
        lib.bindSymbol_stdcall(gnutls_dh_params_export_raw, "gnutls_dh_params_export_raw");
        lib.bindSymbol_stdcall(gnutls_dh_params_cpy, "gnutls_dh_params_cpy");
        lib.bindSymbol_stdcall(gnutls_system_recv_timeout, "gnutls_system_recv_timeout");
        lib.bindSymbol_stdcall(gnutls_transport_set_int2, "gnutls_transport_set_int2");
        lib.bindSymbol_stdcall(gnutls_transport_get_int2, "gnutls_transport_get_int2");
        lib.bindSymbol_stdcall(gnutls_transport_get_int, "gnutls_transport_get_int");
        lib.bindSymbol_stdcall(gnutls_transport_set_ptr, "gnutls_transport_set_ptr");
        lib.bindSymbol_stdcall(gnutls_transport_set_ptr2, "gnutls_transport_set_ptr2");
        lib.bindSymbol_stdcall(gnutls_transport_get_ptr, "gnutls_transport_get_ptr");
        lib.bindSymbol_stdcall(gnutls_transport_get_ptr2, "gnutls_transport_get_ptr2");
        lib.bindSymbol_stdcall(gnutls_transport_set_vec_push_function, "gnutls_transport_set_vec_push_function");
        lib.bindSymbol_stdcall(gnutls_transport_set_push_function, "gnutls_transport_set_push_function");
        lib.bindSymbol_stdcall(gnutls_transport_set_pull_function, "gnutls_transport_set_pull_function");
        lib.bindSymbol_stdcall(gnutls_transport_set_pull_timeout_function, "gnutls_transport_set_pull_timeout_function");
        lib.bindSymbol_stdcall(gnutls_transport_set_errno_function, "gnutls_transport_set_errno_function");
        lib.bindSymbol_stdcall(gnutls_transport_set_errno, "gnutls_transport_set_errno");
        lib.bindSymbol_stdcall(gnutls_session_set_ptr, "gnutls_session_set_ptr");
        lib.bindSymbol_stdcall(gnutls_session_get_ptr, "gnutls_session_get_ptr");
        lib.bindSymbol_stdcall(gnutls_openpgp_send_cert, "gnutls_openpgp_send_cert");
        lib.bindSymbol_stdcall(gnutls_fingerprint, "gnutls_fingerprint");
        lib.bindSymbol_stdcall(gnutls_random_art, "gnutls_random_art");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_9)
        {
            lib.bindSymbol_stdcall(gnutls_idna_map, "gnutls_idna_map");
            lib.bindSymbol_stdcall(gnutls_idna_reverse_map, "gnutls_idna_reverse_map");
        }

        lib.bindSymbol_stdcall(gnutls_srp_free_client_credentials, "gnutls_srp_free_client_credentials");
        lib.bindSymbol_stdcall(gnutls_srp_allocate_client_credentials, "gnutls_srp_allocate_client_credentials");
        lib.bindSymbol_stdcall(gnutls_srp_set_client_credentials, "gnutls_srp_set_client_credentials");
        lib.bindSymbol_stdcall(gnutls_srp_free_server_credentials, "gnutls_srp_free_server_credentials");
        lib.bindSymbol_stdcall(gnutls_srp_allocate_server_credentials, "gnutls_srp_allocate_server_credentials");
        lib.bindSymbol_stdcall(gnutls_srp_set_server_credentials_file, "gnutls_srp_set_server_credentials_file");
        lib.bindSymbol_stdcall(gnutls_srp_server_get_username, "gnutls_srp_server_get_username");
        lib.bindSymbol_stdcall(gnutls_srp_set_prime_bits, "gnutls_srp_set_prime_bits");
        lib.bindSymbol_stdcall(gnutls_srp_verifier, "gnutls_srp_verifier");
        lib.bindSymbol_stdcall(gnutls_srp_set_server_credentials_function, "gnutls_srp_set_server_credentials_function");
        lib.bindSymbol_stdcall(gnutls_srp_set_client_credentials_function, "gnutls_srp_set_client_credentials_function");
        lib.bindSymbol_stdcall(gnutls_srp_base64_encode, "gnutls_srp_base64_encode");
        lib.bindSymbol_stdcall(gnutls_srp_base64_encode2, "gnutls_srp_base64_encode2");
        lib.bindSymbol_stdcall(gnutls_srp_base64_decode, "gnutls_srp_base64_decode");
        lib.bindSymbol_stdcall(gnutls_srp_base64_decode2, "gnutls_srp_base64_decode2");
        lib.bindSymbol_stdcall(gnutls_srp_set_server_fake_salt_seed, "gnutls_srp_set_server_fake_salt_seed");
        lib.bindSymbol_stdcall(gnutls_psk_free_client_credentials, "gnutls_psk_free_client_credentials");
        lib.bindSymbol_stdcall(gnutls_psk_allocate_client_credentials, "gnutls_psk_allocate_client_credentials");
        lib.bindSymbol_stdcall(gnutls_psk_set_client_credentials, "gnutls_psk_set_client_credentials");
        lib.bindSymbol_stdcall(gnutls_psk_free_server_credentials, "gnutls_psk_free_server_credentials");
        lib.bindSymbol_stdcall(gnutls_psk_allocate_server_credentials, "gnutls_psk_allocate_server_credentials");
        lib.bindSymbol_stdcall(gnutls_psk_set_server_credentials_file, "gnutls_psk_set_server_credentials_file");
        lib.bindSymbol_stdcall(gnutls_psk_set_server_credentials_hint, "gnutls_psk_set_server_credentials_hint");
        lib.bindSymbol_stdcall(gnutls_psk_server_get_username, "gnutls_psk_server_get_username");
        lib.bindSymbol_stdcall(gnutls_psk_client_get_hint, "gnutls_psk_client_get_hint");
        lib.bindSymbol_stdcall(gnutls_psk_set_server_credentials_function, "gnutls_psk_set_server_credentials_function");
        lib.bindSymbol_stdcall(gnutls_psk_set_client_credentials_function, "gnutls_psk_set_client_credentials_function");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            lib.bindSymbol_stdcall(gnutls_psk_set_client_credentials2, "gnutls_psk_set_client_credentials2");
            lib.bindSymbol_stdcall(gnutls_psk_server_get_username2, "gnutls_psk_server_get_username2");
            lib.bindSymbol_stdcall(gnutls_psk_set_server_credentials_function2, "gnutls_psk_set_server_credentials_function2");
            lib.bindSymbol_stdcall(gnutls_psk_set_client_credentials_function2, "gnutls_psk_set_client_credentials_function2");
        }

        lib.bindSymbol_stdcall(gnutls_hex_encode, "gnutls_hex_encode");
        lib.bindSymbol_stdcall(gnutls_hex_decode, "gnutls_hex_decode");
        lib.bindSymbol_stdcall(gnutls_hex_encode2, "gnutls_hex_encode2");
        lib.bindSymbol_stdcall(gnutls_hex_decode2, "gnutls_hex_decode2");
        lib.bindSymbol_stdcall(gnutls_psk_set_server_dh_params, "gnutls_psk_set_server_dh_params");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_6)
            lib.bindSymbol_stdcall(gnutls_psk_set_server_known_dh_params, "gnutls_psk_set_server_known_dh_params");

        lib.bindSymbol_stdcall(gnutls_psk_set_server_params_function, "gnutls_psk_set_server_params_function");
        lib.bindSymbol_stdcall(gnutls_auth_get_type, "gnutls_auth_get_type");
        lib.bindSymbol_stdcall(gnutls_auth_server_get_type, "gnutls_auth_server_get_type");
        lib.bindSymbol_stdcall(gnutls_auth_client_get_type, "gnutls_auth_client_get_type");
        lib.bindSymbol_stdcall(gnutls_dh_set_prime_bits, "gnutls_dh_set_prime_bits");
        lib.bindSymbol_stdcall(gnutls_dh_get_secret_bits, "gnutls_dh_get_secret_bits");
        lib.bindSymbol_stdcall(gnutls_dh_get_peers_public_bits, "gnutls_dh_get_peers_public_bits");
        lib.bindSymbol_stdcall(gnutls_dh_get_prime_bits, "gnutls_dh_get_prime_bits");
        lib.bindSymbol_stdcall(gnutls_dh_get_group, "gnutls_dh_get_group");
        lib.bindSymbol_stdcall(gnutls_dh_get_pubkey, "gnutls_dh_get_pubkey");
        lib.bindSymbol_stdcall(gnutls_certificate_set_retrieve_function, "gnutls_certificate_set_retrieve_function");
        lib.bindSymbol_stdcall(gnutls_certificate_set_verify_function, "gnutls_certificate_set_verify_function");
        lib.bindSymbol_stdcall(gnutls_certificate_server_set_request, "gnutls_certificate_server_set_request");
        lib.bindSymbol_stdcall(gnutls_certificate_get_peers, "gnutls_certificate_get_peers");
        lib.bindSymbol_stdcall(gnutls_certificate_get_ours, "gnutls_certificate_get_ours");
        lib.bindSymbol_stdcall(gnutls_certificate_get_peers_subkey_id, "gnutls_certificate_get_peers_subkey_id");
        lib.bindSymbol_stdcall(gnutls_certificate_activation_time_peers, "gnutls_certificate_activation_time_peers");
        lib.bindSymbol_stdcall(gnutls_certificate_expiration_time_peers, "gnutls_certificate_expiration_time_peers");
        lib.bindSymbol_stdcall(gnutls_certificate_client_get_request_status, "gnutls_certificate_client_get_request_status");
        lib.bindSymbol_stdcall(gnutls_certificate_verify_peers2, "gnutls_certificate_verify_peers2");
        lib.bindSymbol_stdcall(gnutls_certificate_verify_peers3, "gnutls_certificate_verify_peers3");
        lib.bindSymbol_stdcall(gnutls_certificate_verify_peers, "gnutls_certificate_verify_peers");
        lib.bindSymbol_stdcall(gnutls_certificate_verification_status_print, "gnutls_certificate_verification_status_print");
        lib.bindSymbol_stdcall(gnutls_pem_base64_encode, "gnutls_pem_base64_encode");
        lib.bindSymbol_stdcall(gnutls_pem_base64_decode, "gnutls_pem_base64_decode");
        lib.bindSymbol_stdcall(gnutls_pem_base64_encode2, "gnutls_pem_base64_encode2");
        lib.bindSymbol_stdcall(gnutls_pem_base64_decode2, "gnutls_pem_base64_decode2");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_base64_encode2, "gnutls_base64_encode2");
            lib.bindSymbol_stdcall(gnutls_base64_decode2, "gnutls_base64_decode2");
        }

        lib.bindSymbol_stdcall(gnutls_certificate_set_params_function, "gnutls_certificate_set_params_function");
        lib.bindSymbol_stdcall(gnutls_anon_set_params_function, "gnutls_anon_set_params_function");
        lib.bindSymbol_stdcall(gnutls_psk_set_params_function, "gnutls_psk_set_params_function");
        lib.bindSymbol_stdcall(gnutls_hex2bin, "gnutls_hex2bin");
        lib.bindSymbol_stdcall(gnutls_tdb_init, "gnutls_tdb_init");
        lib.bindSymbol_stdcall(gnutls_tdb_set_store_func, "gnutls_tdb_set_store_func");
        lib.bindSymbol_stdcall(gnutls_tdb_set_store_commitment_func, "gnutls_tdb_set_store_commitment_func");
        lib.bindSymbol_stdcall(gnutls_tdb_set_verify_func, "gnutls_tdb_set_verify_func");
        lib.bindSymbol_stdcall(gnutls_tdb_deinit, "gnutls_tdb_deinit");
        lib.bindSymbol_stdcall(gnutls_verify_stored_pubkey, "gnutls_verify_stored_pubkey");
        lib.bindSymbol_stdcall(gnutls_store_commitment, "gnutls_store_commitment");
        lib.bindSymbol_stdcall(gnutls_store_pubkey, "gnutls_store_pubkey");
        lib.bindSymbol_stdcall(gnutls_load_file, "gnutls_load_file");
        lib.bindSymbol_stdcall(gnutls_url_is_supported, "gnutls_url_is_supported");
        lib.bindSymbol_stdcall(gnutls_certificate_set_pin_function, "gnutls_certificate_set_pin_function");
        lib.bindSymbol_stdcall(gnutls_buffer_append_data, "gnutls_buffer_append_data");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_7)
            lib.bindSymbol_stdcall(gnutls_utf8_password_normalize, "gnutls_utf8_password_normalize");

        lib.bindSymbol_stdcall(gnutls_ext_set_data, "gnutls_ext_set_data");
        lib.bindSymbol_stdcall(gnutls_ext_get_data, "gnutls_ext_get_data");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            lib.bindSymbol_stdcall(gnutls_ext_get_current_msg, "gnutls_ext_get_current_msg");
            lib.bindSymbol_stdcall(gnutls_ext_raw_parse, "gnutls_ext_raw_parse");
        }

        lib.bindSymbol_stdcall(gnutls_ext_register, "gnutls_ext_register");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            lib.bindSymbol_stdcall(gnutls_session_ext_register, "gnutls_session_ext_register");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_1)
            lib.bindSymbol_stdcall(gnutls_ext_get_name, "gnutls_ext_get_name");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_14)
            lib.bindSymbol_stdcall(gnutls_ext_get_name2, "gnutls_ext_get_name2");

        lib.bindSymbol_stdcall(gnutls_supplemental_register, "gnutls_supplemental_register");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_5)
            lib.bindSymbol_stdcall(gnutls_session_supplemental_register, "gnutls_session_supplemental_register");

        lib.bindSymbol_stdcall(gnutls_supplemental_recv, "gnutls_supplemental_recv");
        lib.bindSymbol_stdcall(gnutls_supplemental_send, "gnutls_supplemental_send");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_5)
        {
            lib.bindSymbol_stdcall(gnutls_anti_replay_init, "gnutls_anti_replay_init");
            lib.bindSymbol_stdcall(gnutls_anti_replay_deinit, "gnutls_anti_replay_deinit");
            lib.bindSymbol_stdcall(gnutls_anti_replay_set_window, "gnutls_anti_replay_set_window");
            lib.bindSymbol_stdcall(gnutls_anti_replay_enable, "gnutls_anti_replay_enable");
            lib.bindSymbol_stdcall(gnutls_anti_replay_set_add_function, "gnutls_anti_replay_set_add_function");
        }

        lib.bindSymbol_stdcall(gnutls_anti_replay_set_ptr, "gnutls_anti_replay_set_ptr");
        lib.bindSymbol_stdcall(gnutls_fips140_mode_enabled, "gnutls_fips140_mode_enabled");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_fips140_set_mode, "gnutls_fips140_set_mode");

    }

    private mixin template externField(T, string symbol)
    {
        import std.traits : isFunctionPointer, Parameters, ReturnType;

        mixin("private __gshared T* " ~ symbol ~ "_;");
        static if (isFunctionPointer!T)
            mixin("ReturnType!T " ~ symbol ~ "(Parameters!T params) { return (*" ~ symbol ~ "_)(params); }");
        else
            mixin("T " ~ symbol ~ "() { return *" ~ symbol ~ "_; }");
    }
}
