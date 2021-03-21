module bindbc.gnutls.dane;

import bindbc.gnutls.gnutls;

extern (C):

enum dane_cert_usage_t
{
    DANE_CERT_USAGE_CA = 0,
    DANE_CERT_USAGE_EE = 1,
    DANE_CERT_USAGE_LOCAL_CA = 2,
    DANE_CERT_USAGE_LOCAL_EE = 3
}

enum dane_cert_type_t
{
    DANE_CERT_X509 = 0,
    DANE_CERT_PK = 1
}

enum dane_match_type_t
{
    DANE_MATCH_EXACT = 0,
    DANE_MATCH_SHA2_256 = 1,
    DANE_MATCH_SHA2_512 = 2
}

enum dane_query_status_t
{
    DANE_QUERY_UNKNOWN = 0,
    DANE_QUERY_DNSSEC_VERIFIED = 1,
    DANE_QUERY_BOGUS = 2,
    DANE_QUERY_NO_DNSSEC = 3
}

struct dane_state_st;
alias dane_state_t = dane_state_st*;
struct dane_query_st;
alias dane_query_t = dane_query_st*;

enum dane_state_flags_t
{
    DANE_F_IGNORE_LOCAL_RESOLVER = 1,
    DANE_F_INSECURE = 2,
    DANE_F_IGNORE_DNSSEC = 4
}

int dane_state_init (dane_state_t* s, uint flags);
int dane_state_set_dlv_file (dane_state_t s, const(char)* file);
void dane_state_deinit (dane_state_t s);

int dane_raw_tlsa (dane_state_t s, dane_query_t* r, char** dane_data, const(int)* dane_data_len, int secure, int bogus);

int dane_query_tlsa (dane_state_t s, dane_query_t* r, const(char)* host, const(char)* proto, uint port);

dane_query_status_t dane_query_status (dane_query_t q);
uint dane_query_entries (dane_query_t q);
int dane_query_data (dane_query_t q, uint idx, uint* usage, uint* type, uint* match, gnutls_datum_t* data);
int dane_query_to_raw_tlsa (dane_query_t q, uint* data_entries, char*** dane_data, int** dane_data_len, int* secure, int* bogus);
void dane_query_deinit (dane_query_t q);

const(char)* dane_cert_type_name (dane_cert_type_t type);
const(char)* dane_match_type_name (dane_match_type_t type);
const(char)* dane_cert_usage_name (dane_cert_usage_t usage);

enum dane_verify_flags_t
{
    DANE_VFLAG_FAIL_IF_NOT_CHECKED = 1,
    DANE_VFLAG_ONLY_CHECK_EE_USAGE = 1 << 1,
    DANE_VFLAG_ONLY_CHECK_CA_USAGE = 1 << 2
}

enum dane_verify_status_t
{
    DANE_VERIFY_CA_CONSTRAINTS_VIOLATED = 1,
    DANE_VERIFY_CERT_DIFFERS = 1 << 1,
    DANE_VERIFY_UNKNOWN_DANE_INFO = 1 << 2
}

enum DANE_VERIFY_CA_CONSTRAINS_VIOLATED = dane_verify_status_t.DANE_VERIFY_CA_CONSTRAINTS_VIOLATED;
enum DANE_VERIFY_NO_DANE_INFO = dane_verify_status_t.DANE_VERIFY_UNKNOWN_DANE_INFO;

int dane_verification_status_print (uint status, gnutls_datum_t* out_, uint flags);

int dane_verify_crt_raw (dane_state_t s, const(gnutls_datum_t)* chain, uint chain_size, gnutls_certificate_type_t chain_type, dane_query_t r, uint sflags, uint vflags, uint* verify);

int dane_verify_crt (dane_state_t s, const(gnutls_datum_t)* chain, uint chain_size, gnutls_certificate_type_t chain_type, const(char)* hostname, const(char)* proto, uint port, uint sflags, uint vflags, uint* verify);

int dane_verify_session_crt (dane_state_t s, gnutls_session_t session, const(char)* hostname, const(char)* proto, uint port, uint sflags, uint vflags, uint* verify);

const(char)* dane_strerror (int error);

enum DANE_E_SUCCESS = 0;
enum DANE_E_INITIALIZATION_ERROR = -1;
enum DANE_E_RESOLVING_ERROR = -2;
enum DANE_E_NO_DANE_DATA = -3;
enum DANE_E_RECEIVED_CORRUPT_DATA = -4;
enum DANE_E_INVALID_DNSSEC_SIG = -5;
enum DANE_E_NO_DNSSEC_SIG = -6;
enum DANE_E_MEMORY_ERROR = -7;
enum DANE_E_REQUESTED_DATA_NOT_AVAILABLE = -8;
enum DANE_E_INVALID_REQUEST = -9;
enum DANE_E_PUBKEY_ERROR = -10;
enum DANE_E_NO_CERT = -11;
enum DANE_E_FILE_ERROR = -12;
enum DANE_E_CERT_ERROR = -13;
enum DANE_E_UNKNOWN_DANE_DATA = -14;
