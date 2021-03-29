module bindbc.gnutls.crypto;

import bindbc.gnutls.config;
import bindbc.gnutls.gnutls;

struct api_cipher_hd_st;
alias gnutls_cipher_hd_t = api_cipher_hd_st*;

struct api_aead_cipher_hd_st;
alias gnutls_aead_cipher_hd_t = api_aead_cipher_hd_st*;

struct hash_hd_st;
alias gnutls_hash_hd_t = hash_hd_st*;

struct hmac_hd_st;
alias gnutls_hmac_hd_t = hmac_hd_st*;

enum gnutls_rnd_level
{
    GNUTLS_RND_NONCE = 0,
    GNUTLS_RND_RANDOM = 1,
    GNUTLS_RND_KEY = 2
}

alias gnutls_rnd_level_t = gnutls_rnd_level;

extern(C) nothrow @nogc
{
    alias gnutls_cipher_init_func = int function (gnutls_cipher_algorithm_t, void** ctx, int enc);
    alias gnutls_cipher_setkey_func = int function (void* ctx, const(void)* key, size_t keysize);
    alias gnutls_cipher_setiv_func = int function (void* ctx, const(void)* iv, size_t ivsize);
    alias gnutls_cipher_getiv_func = int function (void* ctx, void* iv, size_t ivsize);
    alias gnutls_cipher_encrypt_func = int function (void* ctx, const(void)* plain, size_t plainsize, void* encr, size_t encrsize);
    alias gnutls_cipher_decrypt_func = int function (void* ctx, const(void)* encr, size_t encrsize, void* plain, size_t plainsize);
    alias gnutls_cipher_auth_func = int function (void* ctx, const(void)* data, size_t datasize);
    alias gnutls_cipher_tag_func = void function (void* ctx, void* tag, size_t tagsize);
    alias gnutls_cipher_aead_encrypt_func = int function (void* ctx, const(void)* nonce, size_t noncesize, const(void)* auth, size_t authsize, size_t tag_size, const(void)* plain, size_t plainsize, void* encr, size_t encrsize);
    alias gnutls_cipher_aead_decrypt_func = int function (void* ctx, const(void)* nonce, size_t noncesize, const(void)* auth, size_t authsize, size_t tag_size, const(void)* encr, size_t encrsize, void* plain, size_t plainsize);
    alias gnutls_cipher_deinit_func = void function (void* ctx);
    alias gnutls_mac_init_func = int function (gnutls_mac_algorithm_t, void** ctx);
    alias gnutls_mac_setkey_func = int function (void* ctx, const(void)* key, size_t keysize);
    alias gnutls_mac_setnonce_func = int function (void* ctx, const(void)* nonce, size_t noncesize);
    alias gnutls_mac_hash_func = int function (void* ctx, const(void)* text, size_t textsize);
    alias gnutls_mac_output_func = int function (void* src_ctx, void* digest, size_t digestsize);
    alias gnutls_mac_deinit_func = void function (void* ctx);
    alias gnutls_mac_fast_func = int function (gnutls_mac_algorithm_t, const(void)* nonce, size_t nonce_size, const(void)* key, size_t keysize, const(void)* text, size_t textsize, void* digest);
    alias gnutls_mac_copy_func = void* function (const(void)* ctx);
    alias gnutls_digest_init_func = int function (gnutls_digest_algorithm_t, void** ctx);
    alias gnutls_digest_hash_func = int function (void* ctx, const(void)* text, size_t textsize);
    alias gnutls_digest_output_func = int function (void* src_ctx, void* digest, size_t digestsize);
    alias gnutls_digest_deinit_func = void function (void* ctx);
    alias gnutls_digest_fast_func = int function (gnutls_digest_algorithm_t, const(void)* text, size_t textsize, void* digest);
    alias gnutls_digest_copy_func = void* function (const(void)* ctx);
}

version (BindGnuTLS_Static)
{
    extern (System) @nogc nothrow @system:

    int gnutls_cipher_init (gnutls_cipher_hd_t* handle, gnutls_cipher_algorithm_t cipher, const(gnutls_datum_t)* key, const(gnutls_datum_t)* iv);
    int gnutls_cipher_encrypt (const gnutls_cipher_hd_t handle, void* text, size_t textlen);
    int gnutls_cipher_decrypt (const gnutls_cipher_hd_t handle, void* ciphertext, size_t ciphertextlen);
    int gnutls_cipher_decrypt2 (gnutls_cipher_hd_t handle, const(void)* ciphertext, size_t ciphertextlen, void* text, size_t textlen);
    int gnutls_cipher_encrypt2 (gnutls_cipher_hd_t handle, const(void)* text, size_t textlen, void* ciphertext, size_t ciphertextlen);
    void gnutls_cipher_set_iv (gnutls_cipher_hd_t handle, void* iv, size_t ivlen);
    int gnutls_cipher_tag (gnutls_cipher_hd_t handle, void* tag, size_t tag_size);
    int gnutls_cipher_add_auth (gnutls_cipher_hd_t handle, const(void)* text, size_t text_size);
    void gnutls_cipher_deinit (gnutls_cipher_hd_t handle);
    uint gnutls_cipher_get_block_size (gnutls_cipher_algorithm_t algorithm);
    uint gnutls_cipher_get_iv_size (gnutls_cipher_algorithm_t algorithm);
    uint gnutls_cipher_get_tag_size (gnutls_cipher_algorithm_t algorithm);
    int gnutls_aead_cipher_init (gnutls_aead_cipher_hd_t* handle, gnutls_cipher_algorithm_t cipher, const(gnutls_datum_t)* key);
    int gnutls_aead_cipher_decrypt (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(void)* auth, size_t auth_len, size_t tag_size, const(void)* ctext, size_t ctext_len, void* ptext, size_t* ptext_len);
    int gnutls_aead_cipher_encrypt (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(void)* auth, size_t auth_len, size_t tag_size, const(void)* ptext, size_t ptext_len, void* ctext, size_t* ctext_len);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        int gnutls_aead_cipher_encryptv (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, size_t tag_size, const(giovec_t)* iov, int iovcnt, void* ctext, size_t* ctext_len);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_10)
    {
        int gnutls_aead_cipher_encryptv2 (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, const(giovec_t)* iov, int iovcnt, void* tag, size_t* tag_size);
        int gnutls_aead_cipher_decryptv2 (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, const(giovec_t)* iov, int iovcnt, void* tag, size_t tag_size);
    }

    void gnutls_aead_cipher_deinit (gnutls_aead_cipher_hd_t handle);
    size_t gnutls_mac_get_nonce_size (gnutls_mac_algorithm_t algorithm);
    int gnutls_hmac_init (gnutls_hmac_hd_t* dig, gnutls_mac_algorithm_t algorithm, const(void)* key, size_t keylen);
    void gnutls_hmac_set_nonce (gnutls_hmac_hd_t handle, const(void)* nonce, size_t nonce_len);
    int gnutls_hmac (gnutls_hmac_hd_t handle, const(void)* text, size_t textlen);
    void gnutls_hmac_output (gnutls_hmac_hd_t handle, void* digest);
    void gnutls_hmac_deinit (gnutls_hmac_hd_t handle, void* digest);
    uint gnutls_hmac_get_len (gnutls_mac_algorithm_t algorithm);
    uint gnutls_hmac_get_key_size (gnutls_mac_algorithm_t algorithm);
    int gnutls_hmac_fast (gnutls_mac_algorithm_t algorithm, const(void)* key, size_t keylen, const(void)* text, size_t textlen, void* digest);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
        gnutls_hmac_hd_t gnutls_hmac_copy (gnutls_hmac_hd_t handle);

    int gnutls_hash_init (gnutls_hash_hd_t* dig, gnutls_digest_algorithm_t algorithm);
    int gnutls_hash (gnutls_hash_hd_t handle, const(void)* text, size_t textlen);
    void gnutls_hash_output (gnutls_hash_hd_t handle, void* digest);
    void gnutls_hash_deinit (gnutls_hash_hd_t handle, void* digest);
    uint gnutls_hash_get_len (gnutls_digest_algorithm_t algorithm);
    int gnutls_hash_fast (gnutls_digest_algorithm_t algorithm, const(void)* text, size_t textlen, void* digest);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
        gnutls_hash_hd_t gnutls_hash_copy (gnutls_hash_hd_t handle);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
    {
        int gnutls_hkdf_extract (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* salt, void* output);
        int gnutls_hkdf_expand (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* info, void* output, size_t length);
        int gnutls_pbkdf2 (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* salt, uint iter_count, void* output, size_t length);
    }

    int gnutls_rnd (gnutls_rnd_level_t level, void* data, size_t len);
    void gnutls_rnd_refresh ();

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
    {
        deprecated("Deprecated vrom GnuTLS 3.6.9")
        {
            int gnutls_crypto_register_cipher (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_setiv_func setiv, gnutls_cipher_encrypt_func encrypt, gnutls_cipher_decrypt_func decrypt, gnutls_cipher_deinit_func deinit);
            int gnutls_crypto_register_aead_cipher (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_aead_encrypt_func aead_encrypt, gnutls_cipher_aead_decrypt_func aead_decrypt, gnutls_cipher_deinit_func deinit);
            int gnutls_crypto_register_mac (gnutls_mac_algorithm_t mac, int priority, gnutls_mac_init_func init, gnutls_mac_setkey_func setkey, gnutls_mac_setnonce_func setnonce, gnutls_mac_hash_func hash, gnutls_mac_output_func output, gnutls_mac_deinit_func deinit, gnutls_mac_fast_func hash_fast);
            int gnutls_crypto_register_digest (gnutls_digest_algorithm_t digest, int priority, gnutls_digest_init_func init, gnutls_digest_hash_func hash, gnutls_digest_output_func output, gnutls_digest_deinit_func deinit, gnutls_digest_fast_func hash_fast);
        }
    }
    else
    {
        int gnutls_crypto_register_cipher (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_setiv_func setiv, gnutls_cipher_encrypt_func encrypt, gnutls_cipher_decrypt_func decrypt, gnutls_cipher_deinit_func deinit);
        int gnutls_crypto_register_aead_cipher (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_aead_encrypt_func aead_encrypt, gnutls_cipher_aead_decrypt_func aead_decrypt, gnutls_cipher_deinit_func deinit);
        int gnutls_crypto_register_mac (gnutls_mac_algorithm_t mac, int priority, gnutls_mac_init_func init, gnutls_mac_setkey_func setkey, gnutls_mac_setnonce_func setnonce, gnutls_mac_hash_func hash, gnutls_mac_output_func output, gnutls_mac_deinit_func deinit, gnutls_mac_fast_func hash_fast);
        int gnutls_crypto_register_digest (gnutls_digest_algorithm_t digest, int priority, gnutls_digest_init_func init, gnutls_digest_hash_func hash, gnutls_digest_output_func output, gnutls_digest_deinit_func deinit, gnutls_digest_fast_func hash_fast);
    }

    int gnutls_encode_ber_digest_info (gnutls_digest_algorithm_t hash, const(gnutls_datum_t)* digest, gnutls_datum_t* output);
    int gnutls_decode_ber_digest_info (const(gnutls_datum_t)* info, gnutls_digest_algorithm_t* hash, ubyte* digest, uint* digest_size);

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
    {
        int gnutls_decode_rs_value (const(gnutls_datum_t)* sig_value, gnutls_datum_t* r, gnutls_datum_t* s);
        int gnutls_encode_rs_value (gnutls_datum_t* sig_value, const(gnutls_datum_t)* r, const(gnutls_datum_t)* s);
    }
    else
    {
        // workaround to enable these in older versions too (private but exported)
        int _gnutls_decode_ber_rs_raw (const(gnutls_datum_t)* sig_value, gnutls_datum_t* r, gnutls_datum_t* s);
        int _gnutls_encode_ber_rs_raw (gnutls_datum_t* sig_value, const(gnutls_datum_t)* r, const(gnutls_datum_t)* s);
        alias gnutls_decode_rs_value = _gnutls_decode_ber_rs_raw;
        alias gnutls_encode_rs_value = _gnutls_encode_ber_rs_raw;
    }

    static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
    {
        int gnutls_encode_gost_rs_value (gnutls_datum_t* sig_value, const(gnutls_datum_t)* r, const(gnutls_datum_t)* s);
        int gnutls_decode_gost_rs_value (const(gnutls_datum_t)* sig_value, gnutls_datum_t* r, gnutls_datum_t* s);
    }
}
else
{
    extern (System) @nogc nothrow @system
    {
        alias pgnutls_cipher_init = int function (gnutls_cipher_hd_t* handle, gnutls_cipher_algorithm_t cipher, const(gnutls_datum_t)* key, const(gnutls_datum_t)* iv);
        alias pgnutls_cipher_encrypt = int function (const gnutls_cipher_hd_t handle, void* text, size_t textlen);
        alias pgnutls_cipher_decrypt = int function (const gnutls_cipher_hd_t handle, void* ciphertext, size_t ciphertextlen);
        alias pgnutls_cipher_decrypt2 = int function (gnutls_cipher_hd_t handle, const(void)* ciphertext, size_t ciphertextlen, void* text, size_t textlen);
        alias pgnutls_cipher_encrypt2 = int function (gnutls_cipher_hd_t handle, const(void)* text, size_t textlen, void* ciphertext, size_t ciphertextlen);
        alias pgnutls_cipher_set_iv = void function (gnutls_cipher_hd_t handle, void* iv, size_t ivlen);
        alias pgnutls_cipher_tag = int function (gnutls_cipher_hd_t handle, void* tag, size_t tag_size);
        alias pgnutls_cipher_add_auth = int function (gnutls_cipher_hd_t handle, const(void)* text, size_t text_size);
        alias pgnutls_cipher_deinit = void function (gnutls_cipher_hd_t handle);
        alias pgnutls_cipher_get_block_size = uint function (gnutls_cipher_algorithm_t algorithm);
        alias pgnutls_cipher_get_iv_size = uint function (gnutls_cipher_algorithm_t algorithm);
        alias pgnutls_cipher_get_tag_size = uint function (gnutls_cipher_algorithm_t algorithm);
        alias pgnutls_aead_cipher_init = int function (gnutls_aead_cipher_hd_t* handle, gnutls_cipher_algorithm_t cipher, const(gnutls_datum_t)* key);
        alias pgnutls_aead_cipher_decrypt = int function (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(void)* auth, size_t auth_len, size_t tag_size, const(void)* ctext, size_t ctext_len, void* ptext, size_t* ptext_len);
        alias pgnutls_aead_cipher_encrypt = int function (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(void)* auth, size_t auth_len, size_t tag_size, const(void)* ptext, size_t ptext_len, void* ctext, size_t* ctext_len);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            alias pgnutls_aead_cipher_encryptv = int function (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, size_t tag_size, const(giovec_t)* iov, int iovcnt, void* ctext, size_t* ctext_len);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_10)
        {
            alias pgnutls_aead_cipher_encryptv2 = int function (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, const(giovec_t)* iov, int iovcnt, void* tag, size_t* tag_size);
            alias pgnutls_aead_cipher_decryptv2 = int function (gnutls_aead_cipher_hd_t handle, const(void)* nonce, size_t nonce_len, const(giovec_t)* auth_iov, int auth_iovcnt, const(giovec_t)* iov, int iovcnt, void* tag, size_t tag_size);
        }

        alias pgnutls_aead_cipher_deinit = void function (gnutls_aead_cipher_hd_t handle);
        alias pgnutls_mac_get_nonce_size = size_t function (gnutls_mac_algorithm_t algorithm);
        alias pgnutls_hmac_init = int function (gnutls_hmac_hd_t* dig, gnutls_mac_algorithm_t algorithm, const(void)* key, size_t keylen);
        alias pgnutls_hmac_set_nonce = void function (gnutls_hmac_hd_t handle, const(void)* nonce, size_t nonce_len);
        alias pgnutls_hmac = int function (gnutls_hmac_hd_t handle, const(void)* text, size_t textlen);
        alias pgnutls_hmac_output = void function (gnutls_hmac_hd_t handle, void* digest);
        alias pgnutls_hmac_deinit = void function (gnutls_hmac_hd_t handle, void* digest);
        alias pgnutls_hmac_get_len = uint function (gnutls_mac_algorithm_t algorithm);
        alias pgnutls_hmac_get_key_size = uint function (gnutls_mac_algorithm_t algorithm);
        alias pgnutls_hmac_fast = int function (gnutls_mac_algorithm_t algorithm, const(void)* key, size_t keylen, const(void)* text, size_t textlen, void* digest);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            alias pgnutls_hmac_copy = gnutls_hmac_hd_t function (gnutls_hmac_hd_t handle);

        alias pgnutls_hash_init = int function (gnutls_hash_hd_t* dig, gnutls_digest_algorithm_t algorithm);
        alias pgnutls_hash = int function (gnutls_hash_hd_t handle, const(void)* text, size_t textlen);
        alias pgnutls_hash_output = void function (gnutls_hash_hd_t handle, void* digest);
        alias pgnutls_hash_deinit = void function (gnutls_hash_hd_t handle, void* digest);
        alias pgnutls_hash_get_len = uint function (gnutls_digest_algorithm_t algorithm);
        alias pgnutls_hash_fast = int function (gnutls_digest_algorithm_t algorithm, const(void)* text, size_t textlen, void* digest);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            alias pgnutls_hash_copy = gnutls_hash_hd_t function (gnutls_hash_hd_t handle);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            alias pgnutls_hkdf_extract = int function (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* salt, void* output);
            alias pgnutls_hkdf_expand = int function (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* info, void* output, size_t length);
            alias pgnutls_pbkdf2 = int function (gnutls_mac_algorithm_t mac, const(gnutls_datum_t)* key, const(gnutls_datum_t)* salt, uint iter_count, void* output, size_t length);
        }

        alias pgnutls_rnd = int function (gnutls_rnd_level_t level, void* data, size_t len);
        alias pgnutls_rnd_refresh = void function ();
        alias pgnutls_crypto_register_cipher = int function (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_setiv_func setiv, gnutls_cipher_encrypt_func encrypt, gnutls_cipher_decrypt_func decrypt, gnutls_cipher_deinit_func deinit);
        alias pgnutls_crypto_register_aead_cipher = int function (gnutls_cipher_algorithm_t algorithm, int priority, gnutls_cipher_init_func init, gnutls_cipher_setkey_func setkey, gnutls_cipher_aead_encrypt_func aead_encrypt, gnutls_cipher_aead_decrypt_func aead_decrypt, gnutls_cipher_deinit_func deinit);
        alias pgnutls_crypto_register_mac = int function (gnutls_mac_algorithm_t mac, int priority, gnutls_mac_init_func init, gnutls_mac_setkey_func setkey, gnutls_mac_setnonce_func setnonce, gnutls_mac_hash_func hash, gnutls_mac_output_func output, gnutls_mac_deinit_func deinit, gnutls_mac_fast_func hash_fast);
        alias pgnutls_crypto_register_digest = int function (gnutls_digest_algorithm_t digest, int priority, gnutls_digest_init_func init, gnutls_digest_hash_func hash, gnutls_digest_output_func output, gnutls_digest_deinit_func deinit, gnutls_digest_fast_func hash_fast);
        alias pgnutls_encode_ber_digest_info = int function (gnutls_digest_algorithm_t hash, const(gnutls_datum_t)* digest, gnutls_datum_t* output);
        alias pgnutls_decode_ber_digest_info = int function (const(gnutls_datum_t)* info, gnutls_digest_algorithm_t* hash, ubyte* digest, uint* digest_size);

        // Note that these were added in 3.6.0, but are bound using exported private symbols
        alias pgnutls_decode_rs_value = int function (const(gnutls_datum_t)* sig_value, gnutls_datum_t* r, gnutls_datum_t* s);
        alias pgnutls_encode_rs_value = int function (gnutls_datum_t* sig_value, const(gnutls_datum_t)* r, const(gnutls_datum_t)* s);

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            alias pgnutls_encode_gost_rs_value = int function (gnutls_datum_t* sig_value, const(gnutls_datum_t)* r, const(gnutls_datum_t)* s);
            alias pgnutls_decode_gost_rs_value = int function (const(gnutls_datum_t)* sig_value, gnutls_datum_t* r, gnutls_datum_t* s);
        }
    }

    __gshared
    {
        pgnutls_cipher_init gnutls_cipher_init;
        pgnutls_cipher_encrypt gnutls_cipher_encrypt;
        pgnutls_cipher_decrypt gnutls_cipher_decrypt;
        pgnutls_cipher_decrypt2 gnutls_cipher_decrypt2;
        pgnutls_cipher_encrypt2 gnutls_cipher_encrypt2;
        pgnutls_cipher_set_iv gnutls_cipher_set_iv;
        pgnutls_cipher_tag gnutls_cipher_tag;
        pgnutls_cipher_add_auth gnutls_cipher_add_auth;
        pgnutls_cipher_deinit gnutls_cipher_deinit;
        pgnutls_cipher_get_block_size gnutls_cipher_get_block_size;
        pgnutls_cipher_get_iv_size gnutls_cipher_get_iv_size;
        pgnutls_cipher_get_tag_size gnutls_cipher_get_tag_size;
        pgnutls_aead_cipher_init gnutls_aead_cipher_init;
        pgnutls_aead_cipher_decrypt gnutls_aead_cipher_decrypt;
        pgnutls_aead_cipher_encrypt gnutls_aead_cipher_encrypt;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            pgnutls_aead_cipher_encryptv gnutls_aead_cipher_encryptv;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_10)
        {
            pgnutls_aead_cipher_encryptv2 gnutls_aead_cipher_encryptv2;
            pgnutls_aead_cipher_decryptv2 gnutls_aead_cipher_decryptv2;
        }

        pgnutls_aead_cipher_deinit gnutls_aead_cipher_deinit;
        pgnutls_mac_get_nonce_size gnutls_mac_get_nonce_size;
        pgnutls_hmac_init gnutls_hmac_init;
        pgnutls_hmac_set_nonce gnutls_hmac_set_nonce;
        pgnutls_hmac gnutls_hmac;
        pgnutls_hmac_output gnutls_hmac_output;
        pgnutls_hmac_deinit gnutls_hmac_deinit;
        pgnutls_hmac_get_len gnutls_hmac_get_len;
        pgnutls_hmac_get_key_size gnutls_hmac_get_key_size;
        pgnutls_hmac_fast gnutls_hmac_fast;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            pgnutls_hmac_copy gnutls_hmac_copy;

        pgnutls_hash_init gnutls_hash_init;
        pgnutls_hash gnutls_hash;
        pgnutls_hash_output gnutls_hash_output;
        pgnutls_hash_deinit gnutls_hash_deinit;
        pgnutls_hash_get_len gnutls_hash_get_len;
        pgnutls_hash_fast gnutls_hash_fast;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            pgnutls_hash_copy gnutls_hash_copy;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            pgnutls_hkdf_extract gnutls_hkdf_extract;
            pgnutls_hkdf_expand gnutls_hkdf_expand;
            pgnutls_pbkdf2 gnutls_pbkdf2;
        }

        pgnutls_rnd gnutls_rnd;
        pgnutls_rnd_refresh gnutls_rnd_refresh;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
        {
            deprecated("Deprecated vrom GnuTLS 3.6.9")
            {
                pgnutls_crypto_register_cipher gnutls_crypto_register_cipher;
                pgnutls_crypto_register_aead_cipher gnutls_crypto_register_aead_cipher;
                pgnutls_crypto_register_mac gnutls_crypto_register_mac;
                pgnutls_crypto_register_digest gnutls_crypto_register_digest;
            }
        }
        else
        {
            pgnutls_crypto_register_cipher gnutls_crypto_register_cipher;
            pgnutls_crypto_register_aead_cipher gnutls_crypto_register_aead_cipher;
            pgnutls_crypto_register_mac gnutls_crypto_register_mac;
            pgnutls_crypto_register_digest gnutls_crypto_register_digest;
        }

        pgnutls_encode_ber_digest_info gnutls_encode_ber_digest_info;
        pgnutls_decode_ber_digest_info gnutls_decode_ber_digest_info;

        // Note that these were added in 3.6.0, but are bound using exported private symbols
        pgnutls_decode_rs_value gnutls_decode_rs_value;
        pgnutls_encode_rs_value gnutls_encode_rs_value;

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            pgnutls_encode_gost_rs_value gnutls_encode_gost_rs_value;
            pgnutls_decode_gost_rs_value gnutls_decode_gost_rs_value;
        }
    }

    import bindbc.loader : SharedLib, bindSymbol_stdcall;
    void bindCrypto(SharedLib lib)
    {
        lib.bindSymbol_stdcall(gnutls_cipher_init, "gnutls_cipher_init");
        lib.bindSymbol_stdcall(gnutls_cipher_encrypt, "gnutls_cipher_encrypt");
        lib.bindSymbol_stdcall(gnutls_cipher_decrypt, "gnutls_cipher_decrypt");
        lib.bindSymbol_stdcall(gnutls_cipher_decrypt2, "gnutls_cipher_decrypt2");
        lib.bindSymbol_stdcall(gnutls_cipher_encrypt2, "gnutls_cipher_encrypt2");
        lib.bindSymbol_stdcall(gnutls_cipher_set_iv, "gnutls_cipher_set_iv");
        lib.bindSymbol_stdcall(gnutls_cipher_tag, "gnutls_cipher_tag");
        lib.bindSymbol_stdcall(gnutls_cipher_add_auth, "gnutls_cipher_add_auth");
        lib.bindSymbol_stdcall(gnutls_cipher_deinit, "gnutls_cipher_deinit");
        lib.bindSymbol_stdcall(gnutls_cipher_get_block_size, "gnutls_cipher_get_block_size");
        lib.bindSymbol_stdcall(gnutls_cipher_get_iv_size, "gnutls_cipher_get_iv_size");
        lib.bindSymbol_stdcall(gnutls_cipher_get_tag_size, "gnutls_cipher_get_tag_size");
        lib.bindSymbol_stdcall(gnutls_aead_cipher_init, "gnutls_aead_cipher_init");
        lib.bindSymbol_stdcall(gnutls_aead_cipher_decrypt, "gnutls_aead_cipher_decrypt");
        lib.bindSymbol_stdcall(gnutls_aead_cipher_encrypt, "gnutls_aead_cipher_encrypt");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
            lib.bindSymbol_stdcall(gnutls_aead_cipher_encryptv, "gnutls_aead_cipher_encryptv");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_10)
        {
            lib.bindSymbol_stdcall(gnutls_aead_cipher_encryptv2, "gnutls_aead_cipher_encryptv2");
            lib.bindSymbol_stdcall(gnutls_aead_cipher_decryptv2, "gnutls_aead_cipher_decryptv2");
        }

        lib.bindSymbol_stdcall(gnutls_aead_cipher_deinit, "gnutls_aead_cipher_deinit");
        lib.bindSymbol_stdcall(gnutls_mac_get_nonce_size, "gnutls_mac_get_nonce_size");
        lib.bindSymbol_stdcall(gnutls_hmac_init, "gnutls_hmac_init");
        lib.bindSymbol_stdcall(gnutls_hmac_set_nonce, "gnutls_hmac_set_nonce");
        lib.bindSymbol_stdcall(gnutls_hmac, "gnutls_hmac");
        lib.bindSymbol_stdcall(gnutls_hmac_output, "gnutls_hmac_output");
        lib.bindSymbol_stdcall(gnutls_hmac_deinit, "gnutls_hmac_deinit");
        lib.bindSymbol_stdcall(gnutls_hmac_get_len, "gnutls_hmac_get_len");
        lib.bindSymbol_stdcall(gnutls_hmac_get_key_size, "gnutls_hmac_get_key_size");
        lib.bindSymbol_stdcall(gnutls_hmac_fast, "gnutls_hmac_fast");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            lib.bindSymbol_stdcall(gnutls_hmac_copy, "gnutls_hmac_copy");

        lib.bindSymbol_stdcall(gnutls_hash_init, "gnutls_hash_init");
        lib.bindSymbol_stdcall(gnutls_hash, "gnutls_hash");
        lib.bindSymbol_stdcall(gnutls_hash_output, "gnutls_hash_output");
        lib.bindSymbol_stdcall(gnutls_hash_deinit, "gnutls_hash_deinit");
        lib.bindSymbol_stdcall(gnutls_hash_get_len, "gnutls_hash_get_len");
        lib.bindSymbol_stdcall(gnutls_hash_fast, "gnutls_hash_fast");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_9)
            lib.bindSymbol_stdcall(gnutls_hash_copy, "gnutls_hash_copy");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_13)
        {
            lib.bindSymbol_stdcall(gnutls_hkdf_extract, "gnutls_hkdf_extract");
            lib.bindSymbol_stdcall(gnutls_hkdf_expand, "gnutls_hkdf_expand");
            lib.bindSymbol_stdcall(gnutls_pbkdf2, "gnutls_pbkdf2");
        }

        lib.bindSymbol_stdcall(gnutls_rnd, "gnutls_rnd");
        lib.bindSymbol_stdcall(gnutls_rnd_refresh, "gnutls_rnd_refresh");
        lib.bindSymbol_stdcall(gnutls_crypto_register_cipher, "gnutls_crypto_register_cipher");
        lib.bindSymbol_stdcall(gnutls_crypto_register_aead_cipher, "gnutls_crypto_register_aead_cipher");
        lib.bindSymbol_stdcall(gnutls_crypto_register_mac, "gnutls_crypto_register_mac");
        lib.bindSymbol_stdcall(gnutls_crypto_register_digest, "gnutls_crypto_register_digest");
        lib.bindSymbol_stdcall(gnutls_encode_ber_digest_info, "gnutls_encode_ber_digest_info");
        lib.bindSymbol_stdcall(gnutls_decode_ber_digest_info, "gnutls_decode_ber_digest_info");

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_0)
        {
            lib.bindSymbol_stdcall(gnutls_decode_rs_value, "gnutls_decode_rs_value");
            lib.bindSymbol_stdcall(gnutls_encode_rs_value, "gnutls_encode_rs_value");
        }
        else
        {
            // workaround to enable these even with the older GnuTLS libs
            lib.bindSymbol_stdcall(gnutls_decode_rs_value, "_gnutls_decode_ber_rs_raw");
            lib.bindSymbol_stdcall(gnutls_encode_rs_value, "_gnutls_encode_ber_rs_raw");
        }

        static if (gnuTLSSupport >= GnuTLSSupport.gnutls_3_6_3)
        {
            lib.bindSymbol_stdcall(gnutls_encode_gost_rs_value, "gnutls_encode_gost_rs_value");
            lib.bindSymbol_stdcall(gnutls_decode_gost_rs_value, "gnutls_decode_gost_rs_value");
        }
    }
}
