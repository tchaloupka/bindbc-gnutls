module bindbc.gnutls;

public import bindbc.gnutls.abstract_;
public import bindbc.gnutls.config;
public import bindbc.gnutls.crypto;
public import bindbc.gnutls.dane;
public import bindbc.gnutls.dtls;
public import bindbc.gnutls.gnutls;
public import bindbc.gnutls.ocsp;
public import bindbc.gnutls.openpgp;
public import bindbc.gnutls.pkcs7;
public import bindbc.gnutls.pkcs11;
public import bindbc.gnutls.pkcs12;
public import bindbc.gnutls.self_test;
public import bindbc.gnutls.socket;
public import bindbc.gnutls.system_keys;
public import bindbc.gnutls.tpm;
public import bindbc.gnutls.urls;
public import bindbc.gnutls.x509_ext;
public import bindbc.gnutls.x509;

version (BindGnuTLS_Static) {}
else {
    import bindbc.loader;

    private SharedLib lib, libDane;

    GnuTLSSupport loadGnuTLS()
    {
        version(Windows) {
            const(char)[][2] libNames = [
                "libgnutls.dll",
                "libgnutls-30.dll"
            ];
        }
        else version(Posix) {
            const(char)[][2] libNames = [
                "libgnutls.so",
                "libgnutls.so.30"
            ];
        }
        else static assert(0, "bindbc-gnutls is not yet supported on this platform.");

        GnuTLSSupport ret;
        foreach (name; libNames) {
            ret = loadGnuTLS(name.ptr);
            if (ret != GnuTLSSupport.noLibrary) break;
        }
        return ret;
    }

    GnuTLSSupport loadGnuTLS_Dane()
    {
        version(Posix) {
            const(char)[][2] libNames = [
                "libgnutls-dane.so",
                "libgnutls-dane.so.0"
            ];
        }
        else static assert(0, "bindbc-gnutls-dane is not yet supported on this platform.");

        GnuTLSSupport ret;
        foreach (name; libNames) {
            ret = loadGnuTLS_Dane(name.ptr);
            if (ret != GnuTLSSupport.noLibrary) break;
        }
        return ret;
    }

    GnuTLSSupport loadGnuTLS(const(char)* libName)
    {
        // If the library isn't yet loaded, load it now.
        if (lib == invalidHandle)
        {
            lib = load(libName);
            if (lib == invalidHandle) return GnuTLSSupport.noLibrary;
        }

        immutable errCount = errorCount();

        // Bind functions from individual modules
        lib.bindAbstract();
        lib.bindCrypto();
        lib.bindDtls();
        lib.bindGnutls();
        lib.bindOcsp();
        lib.bindOpenPGP();
        lib.bindPkcs7();
        lib.bindPkcs11();
        lib.bindPkcs12();
        lib.bindSelfTest();

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_5_3)
            lib.bindSocket();

        lib.bindSystemKeys();
        lib.bindTpm();
        lib.bindUrls();
        lib.bindX509Ext();
        lib.bindX509();

        if (errorCount() != errCount) return GnuTLSSupport.badLibrary;
        return gnuTLSSupport;
    }

    GnuTLSSupport loadGnuTLS_Dane(const(char)* libName)
    {
        // If the library isn't yet loaded, load it now.
        if (libDane == invalidHandle)
        {
            libDane = load(libName);
            if (libDane == invalidHandle) return GnuTLSSupport.noLibrary;
        }

        immutable errCount = errorCount();

        libDane.bindDane();

        if (errorCount() != errCount) return GnuTLSSupport.badLibrary;
        return gnuTLSSupport;
    }
}
