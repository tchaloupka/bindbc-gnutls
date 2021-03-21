module bindbc.gnutls.ocsp;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import core.sys.posix.sys.select;

extern (C):

enum GNUTLS_OCSP_NONCE = "1.3.6.1.5.5.7.48.1.2";

enum gnutls_ocsp_print_formats_t
{
    GNUTLS_OCSP_PRINT_FULL = 0,
    GNUTLS_OCSP_PRINT_COMPACT = 1
}

enum gnutls_ocsp_resp_status_t
{
    GNUTLS_OCSP_RESP_SUCCESSFUL = 0,
    GNUTLS_OCSP_RESP_MALFORMEDREQUEST = 1,
    GNUTLS_OCSP_RESP_INTERNALERROR = 2,
    GNUTLS_OCSP_RESP_TRYLATER = 3,
    GNUTLS_OCSP_RESP_SIGREQUIRED = 5,
    GNUTLS_OCSP_RESP_UNAUTHORIZED = 6
}

enum gnutls_ocsp_cert_status_t
{
    GNUTLS_OCSP_CERT_GOOD = 0,
    GNUTLS_OCSP_CERT_REVOKED = 1,
    GNUTLS_OCSP_CERT_UNKNOWN = 2
}

enum gnutls_x509_crl_reason_t
{
    GNUTLS_X509_CRLREASON_UNSPECIFIED = 0,
    GNUTLS_X509_CRLREASON_KEYCOMPROMISE = 1,
    GNUTLS_X509_CRLREASON_CACOMPROMISE = 2,
    GNUTLS_X509_CRLREASON_AFFILIATIONCHANGED = 3,
    GNUTLS_X509_CRLREASON_SUPERSEDED = 4,
    GNUTLS_X509_CRLREASON_CESSATIONOFOPERATION = 5,
    GNUTLS_X509_CRLREASON_CERTIFICATEHOLD = 6,
    GNUTLS_X509_CRLREASON_REMOVEFROMCRL = 8,
    GNUTLS_X509_CRLREASON_PRIVILEGEWITHDRAWN = 9,
    GNUTLS_X509_CRLREASON_AACOMPROMISE = 10
}

enum gnutls_ocsp_verify_reason_t
{
    GNUTLS_OCSP_VERIFY_SIGNER_NOT_FOUND = 1,
    GNUTLS_OCSP_VERIFY_SIGNER_KEYUSAGE_ERROR = 2,
    GNUTLS_OCSP_VERIFY_UNTRUSTED_SIGNER = 4,
    GNUTLS_OCSP_VERIFY_INSECURE_ALGORITHM = 8,
    GNUTLS_OCSP_VERIFY_SIGNATURE_FAILURE = 16,
    GNUTLS_OCSP_VERIFY_CERT_NOT_ACTIVATED = 32,
    GNUTLS_OCSP_VERIFY_CERT_EXPIRED = 64
}

struct gnutls_ocsp_req_int;
alias gnutls_ocsp_req_t = gnutls_ocsp_req_int*;
alias gnutls_ocsp_req_const_t = const(gnutls_ocsp_req_int)*;

int gnutls_ocsp_req_init (gnutls_ocsp_req_t* req);
void gnutls_ocsp_req_deinit (gnutls_ocsp_req_t req);

int gnutls_ocsp_req_import (gnutls_ocsp_req_t req, const(gnutls_datum_t)* data);
int gnutls_ocsp_req_export (gnutls_ocsp_req_const_t req, gnutls_datum_t* data);
int gnutls_ocsp_req_print (gnutls_ocsp_req_const_t req, gnutls_ocsp_print_formats_t format, gnutls_datum_t* out_);

int gnutls_ocsp_req_get_version (gnutls_ocsp_req_const_t req);

int gnutls_ocsp_req_get_cert_id (gnutls_ocsp_req_const_t req, uint indx, gnutls_digest_algorithm_t* digest, gnutls_datum_t* issuer_name_hash, gnutls_datum_t* issuer_key_hash, gnutls_datum_t* serial_number);
int gnutls_ocsp_req_add_cert_id (gnutls_ocsp_req_t req, gnutls_digest_algorithm_t digest, const(gnutls_datum_t)* issuer_name_hash, const(gnutls_datum_t)* issuer_key_hash, const(gnutls_datum_t)* serial_number);
int gnutls_ocsp_req_add_cert (gnutls_ocsp_req_t req, gnutls_digest_algorithm_t digest, gnutls_x509_crt_t issuer, gnutls_x509_crt_t cert);

int gnutls_ocsp_req_get_extension (gnutls_ocsp_req_const_t req, uint indx, gnutls_datum_t* oid, uint* critical, gnutls_datum_t* data);
int gnutls_ocsp_req_set_extension (gnutls_ocsp_req_t req, const(char)* oid, uint critical, const(gnutls_datum_t)* data);

int gnutls_ocsp_req_get_nonce (gnutls_ocsp_req_const_t req, uint* critical, gnutls_datum_t* nonce);
int gnutls_ocsp_req_set_nonce (gnutls_ocsp_req_t req, uint critical, const(gnutls_datum_t)* nonce);
int gnutls_ocsp_req_randomize_nonce (gnutls_ocsp_req_t req);

struct gnutls_ocsp_resp_int;
alias gnutls_ocsp_resp_t = gnutls_ocsp_resp_int*;
alias gnutls_ocsp_resp_const_t = const(gnutls_ocsp_resp_int)*;

int gnutls_ocsp_resp_init (gnutls_ocsp_resp_t* resp);
void gnutls_ocsp_resp_deinit (gnutls_ocsp_resp_t resp);

int gnutls_ocsp_resp_import (gnutls_ocsp_resp_t resp, const(gnutls_datum_t)* data);
int gnutls_ocsp_resp_import2 (gnutls_ocsp_resp_t resp, const(gnutls_datum_t)* data, gnutls_x509_crt_fmt_t fmt);
int gnutls_ocsp_resp_export (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* data);
int gnutls_ocsp_resp_export2 (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* data, gnutls_x509_crt_fmt_t fmt);
int gnutls_ocsp_resp_print (gnutls_ocsp_resp_const_t resp, gnutls_ocsp_print_formats_t format, gnutls_datum_t* out_);

int gnutls_ocsp_resp_get_status (gnutls_ocsp_resp_const_t resp);
int gnutls_ocsp_resp_get_response (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* response_type_oid, gnutls_datum_t* response);

int gnutls_ocsp_resp_get_version (gnutls_ocsp_resp_const_t resp);
int gnutls_ocsp_resp_get_responder (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* dn);
int gnutls_ocsp_resp_get_responder2 (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* dn, uint flags);

enum GNUTLS_OCSP_RESP_ID_KEY = 1;

enum GNUTLS_OCSP_RESP_ID_DN = 2;
int gnutls_ocsp_resp_get_responder_raw_id (gnutls_ocsp_resp_const_t resp, uint type, gnutls_datum_t* raw);

time_t gnutls_ocsp_resp_get_produced (gnutls_ocsp_resp_const_t resp);
int gnutls_ocsp_resp_get_single (gnutls_ocsp_resp_const_t resp, uint indx, gnutls_digest_algorithm_t* digest, gnutls_datum_t* issuer_name_hash, gnutls_datum_t* issuer_key_hash, gnutls_datum_t* serial_number, uint* cert_status, time_t* this_update, time_t* next_update, time_t* revocation_time, uint* revocation_reason);
int gnutls_ocsp_resp_get_extension (gnutls_ocsp_resp_const_t resp, uint indx, gnutls_datum_t* oid, uint* critical, gnutls_datum_t* data);
int gnutls_ocsp_resp_get_nonce (gnutls_ocsp_resp_const_t resp, uint* critical, gnutls_datum_t* nonce);
int gnutls_ocsp_resp_get_signature_algorithm (gnutls_ocsp_resp_const_t resp);
int gnutls_ocsp_resp_get_signature (gnutls_ocsp_resp_const_t resp, gnutls_datum_t* sig);
int gnutls_ocsp_resp_get_certs (gnutls_ocsp_resp_const_t resp, gnutls_x509_crt_t** certs, size_t* ncerts);

int gnutls_ocsp_resp_verify_direct (gnutls_ocsp_resp_const_t resp, gnutls_x509_crt_t issuer, uint* verify, uint flags);
int gnutls_ocsp_resp_verify (gnutls_ocsp_resp_const_t resp, gnutls_x509_trust_list_t trustlist, uint* verify, uint flags);

int gnutls_ocsp_resp_check_crt (gnutls_ocsp_resp_const_t resp, uint indx, gnutls_x509_crt_t crt);

int gnutls_ocsp_resp_list_import2 (gnutls_ocsp_resp_t** ocsps, uint* size, const(gnutls_datum_t)* resp_data, gnutls_x509_crt_fmt_t format, uint flags);
