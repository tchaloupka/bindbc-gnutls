module bindbc.gnutls.socket;

import bindbc.gnutls.gnutls;
import core.sys.posix.sys.socket;

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:
    void gnutls_transport_set_fastopen (gnutls_session_t session, int fd, sockaddr* connect_addr, socklen_t connect_addrlen, uint flags);
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_transport_set_fastopen = void function (gnutls_session_t session, int fd, sockaddr* connect_addr, socklen_t connect_addrlen, uint flags);
    }

    __gshared
    {
        pgnutls_transport_set_fastopen gnutls_transport_set_fastopen;
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindSocket(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_transport_set_fastopen, "gnutls_transport_set_fastopen");
    }
}
