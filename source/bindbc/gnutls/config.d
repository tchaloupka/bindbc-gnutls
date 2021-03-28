module bindbc.gnutls.config;

/**
 * List of supported versions
 *
 * Note that missing versions between others means that they just hasn't changed the API so are compatible wit previous one.
 */
enum GnuTLSSupport
{
    noLibrary,      // no GnuTLS library found
    badLibrary,     // there were problems loading library in a required version
    gnutls_3_5_0,
    gnutls_3_5_1,
    gnutls_3_5_3,
    gnutls_3_5_4,
    gnutls_3_5_5,
    gnutls_3_5_6,
    gnutls_3_5_7,
    gnutls_3_5_9,
    gnutls_3_6_0,
    gnutls_3_6_2,
    gnutls_3_6_3,
    gnutls_3_6_4,
    gnutls_3_6_5,
    gnutls_3_6_6,
    gnutls_3_6_8,
    gnutls_3_6_9,
    gnutls_3_6_10,
    gnutls_3_6_12,
    gnutls_3_6_13,
    gnutls_3_6_14,
}

version (GNUTLS_3_5_1) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_1;
else version (GNUTLS_3_5_3) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_3;
else version (GNUTLS_3_5_4) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_4;
else version (GNUTLS_3_5_5) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_5;
else version (GNUTLS_3_5_6) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_6;
else version (GNUTLS_3_5_7) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_7;
else version (GNUTLS_3_5_9) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_9;
else version (GNUTLS_3_6_0) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_0;
else version (GNUTLS_3_6_2) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_2;
else version (GNUTLS_3_6_3) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_3;
else version (GNUTLS_3_6_4) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_4;
else version (GNUTLS_3_6_5) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_5;
else version (GNUTLS_3_6_8) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_8;
else version (GNUTLS_3_6_9) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_9;
else version (GNUTLS_3_6_10) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_10;
else version (GNUTLS_3_6_12) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_12;
else version (GNUTLS_3_6_13) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_13;
else version (GNUTLS_3_6_14) enum gnuTLSSupport = GnuTLSSupport.gnutls_3_6_14;
else enum gnuTLSSupport = GnuTLSSupport.gnutls_3_5_0;
