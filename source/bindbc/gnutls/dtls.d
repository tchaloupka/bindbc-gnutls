module bindbc.gnutls.dtls;

import bindbc.gnutls.gnutls;

enum GNUTLS_COOKIE_KEY_SIZE = 16;

struct gnutls_dtls_prestate_st
{
    uint record_seq;
    uint hsk_read_seq;
    uint hsk_write_seq;
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    void gnutls_dtls_set_timeouts (gnutls_session_t session, uint retrans_timeout, uint total_timeout);
    uint gnutls_dtls_get_mtu (gnutls_session_t session);
    uint gnutls_dtls_get_data_mtu (gnutls_session_t session);
    void gnutls_dtls_set_mtu (gnutls_session_t session, uint mtu);
    int gnutls_dtls_set_data_mtu (gnutls_session_t session, uint mtu);
    uint gnutls_dtls_get_timeout (gnutls_session_t session);
    int gnutls_dtls_cookie_send (gnutls_datum_t* key, void* client_data, size_t client_data_size, gnutls_dtls_prestate_st* prestate, gnutls_transport_ptr_t ptr, gnutls_push_func push_func);
    int gnutls_dtls_cookie_verify (gnutls_datum_t* key, void* client_data, size_t client_data_size, void* _msg, size_t msg_size, gnutls_dtls_prestate_st* prestate);
    void gnutls_dtls_prestate_set (gnutls_session_t session, gnutls_dtls_prestate_st* prestate);
    uint gnutls_record_get_discarded (gnutls_session_t session);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_dtls_set_timeouts = void function (gnutls_session_t session, uint retrans_timeout, uint total_timeout);
        alias pgnutls_dtls_get_mtu = uint function (gnutls_session_t session);
        alias pgnutls_dtls_get_data_mtu = uint function (gnutls_session_t session);
        alias pgnutls_dtls_set_mtu = void function (gnutls_session_t session, uint mtu);
        alias pgnutls_dtls_set_data_mtu = int function (gnutls_session_t session, uint mtu);
        alias pgnutls_dtls_get_timeout = uint function (gnutls_session_t session);
        alias pgnutls_dtls_cookie_send = int function (gnutls_datum_t* key, void* client_data, size_t client_data_size, gnutls_dtls_prestate_st* prestate, gnutls_transport_ptr_t ptr, gnutls_push_func push_func);
        alias pgnutls_dtls_cookie_verify = int function (gnutls_datum_t* key, void* client_data, size_t client_data_size, void* _msg, size_t msg_size, gnutls_dtls_prestate_st* prestate);
        alias pgnutls_dtls_prestate_set = void function (gnutls_session_t session, gnutls_dtls_prestate_st* prestate);
        alias pgnutls_record_get_discarded = uint function (gnutls_session_t session);
    }

    __gshared
    {
        pgnutls_dtls_set_timeouts gnutls_dtls_set_timeouts;
        pgnutls_dtls_get_mtu gnutls_dtls_get_mtu;
        pgnutls_dtls_get_data_mtu gnutls_dtls_get_data_mtu;
        pgnutls_dtls_set_mtu gnutls_dtls_set_mtu;
        pgnutls_dtls_set_data_mtu gnutls_dtls_set_data_mtu;
        pgnutls_dtls_get_timeout gnutls_dtls_get_timeout;
        pgnutls_dtls_cookie_send gnutls_dtls_cookie_send;
        pgnutls_dtls_cookie_verify gnutls_dtls_cookie_verify;
        pgnutls_dtls_prestate_set gnutls_dtls_prestate_set;
        pgnutls_record_get_discarded gnutls_record_get_discarded;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindDtls(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_dtls_set_timeouts, "gnutls_dtls_set_timeouts");
        lib.bindSymbol_stdcall(gnutls_dtls_get_mtu, "gnutls_dtls_get_mtu");
        lib.bindSymbol_stdcall(gnutls_dtls_get_data_mtu, "gnutls_dtls_get_data_mtu");
        lib.bindSymbol_stdcall(gnutls_dtls_set_mtu, "gnutls_dtls_set_mtu");
        lib.bindSymbol_stdcall(gnutls_dtls_set_data_mtu, "gnutls_dtls_set_data_mtu");
        lib.bindSymbol_stdcall(gnutls_dtls_get_timeout, "gnutls_dtls_get_timeout");
        lib.bindSymbol_stdcall(gnutls_dtls_cookie_send, "gnutls_dtls_cookie_send");
        lib.bindSymbol_stdcall(gnutls_dtls_cookie_verify, "gnutls_dtls_cookie_verify");
        lib.bindSymbol_stdcall(gnutls_dtls_prestate_set, "gnutls_dtls_prestate_set");
        lib.bindSymbol_stdcall(gnutls_record_get_discarded, "gnutls_record_get_discarded");
    }
}
