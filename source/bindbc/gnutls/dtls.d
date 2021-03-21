module bindbc.gnutls.dtls;

import bindbc.gnutls.gnutls;

extern (C):

enum GNUTLS_COOKIE_KEY_SIZE = 16;

void gnutls_dtls_set_timeouts (gnutls_session_t session, uint retrans_timeout, uint total_timeout);

uint gnutls_dtls_get_mtu (gnutls_session_t session);
uint gnutls_dtls_get_data_mtu (gnutls_session_t session);

void gnutls_dtls_set_mtu (gnutls_session_t session, uint mtu);
int gnutls_dtls_set_data_mtu (gnutls_session_t session, uint mtu);

uint gnutls_dtls_get_timeout (gnutls_session_t session);

struct gnutls_dtls_prestate_st
{
    uint record_seq;
    uint hsk_read_seq;
    uint hsk_write_seq;
}

int gnutls_dtls_cookie_send (gnutls_datum_t* key, void* client_data, size_t client_data_size, gnutls_dtls_prestate_st* prestate, gnutls_transport_ptr_t ptr, gnutls_push_func push_func);

int gnutls_dtls_cookie_verify (gnutls_datum_t* key, void* client_data, size_t client_data_size, void* _msg, size_t msg_size, gnutls_dtls_prestate_st* prestate);

void gnutls_dtls_prestate_set (gnutls_session_t session, gnutls_dtls_prestate_st* prestate);

uint gnutls_record_get_discarded (gnutls_session_t session);
