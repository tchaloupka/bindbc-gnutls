module bindbc.gnutls.socket;

import bindbc.gnutls.gnutls;
import core.sys.posix.sys.socket;

extern (C):

void gnutls_transport_set_fastopen (gnutls_session_t session, int fd, sockaddr* connect_addr, socklen_t connect_addrlen, uint flags);
