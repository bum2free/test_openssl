#include <iostream>

#include <openssl/engine.h>

#include "custom_hook.h"

static EVP_PKEY *__tee_load_privkey(ENGINE *e1, const char *key_id, UI_METHOD *ui_method, void *callback_data) {
    // Create an RSA object that is associated with this engine so it inherits engine RSA_METHOD
    RSA *rsa_key = RSA_new_method(e1);
    if (!rsa_key) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Fetch public components from secure storage / simulated key (no private d exposed)
    unsigned char modulus_buf[512];
    unsigned char exponent_buf[8];
    int modulus_len = sizeof(modulus_buf);
    int exponent_len = sizeof(exponent_buf);
    if (!secure_get_public_key_modulus(modulus_buf, &modulus_len) ||
        !secure_get_public_key_exponent(exponent_buf, &exponent_len)) {
        RSA_free(rsa_key);
        return NULL;
    }

    BIGNUM *n = BN_bin2bn(modulus_buf, modulus_len, NULL);
    BIGNUM *e = BN_bin2bn(exponent_buf, exponent_len, NULL);
    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa_key);
        return NULL;
    }
    if (!RSA_set0_key(rsa_key, n, e, NULL)) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa_key);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa_key);
        return NULL;
    }
    EVP_PKEY_assign_RSA(pkey, rsa_key); // pkey owns rsa_key now
    return pkey;
}

int create_custom_engine(const char *engine_id, const char *engine_name, const char* test_key_file)
{
    int ret = -1;
    ENGINE *engine = nullptr;
    RSA_METHOD *tee_rsa_method = nullptr;
    if (!init_test_rsa_key(test_key_file)) {
        std::cerr << "Failed to initialize test RSA key" << std::endl;
        return ret;
    }

    engine = ENGINE_new();
    if(!engine)
        return ret;

    if (!ENGINE_set_id(engine, engine_id) || !ENGINE_set_name(engine, engine_name)) {
        ERR_print_errors_fp(stderr);
        goto END;
    }

    tee_rsa_method = RSA_meth_new("TEE RSA method", 0);
    if (!tee_rsa_method) {
        ERR_print_errors_fp(stderr);
        goto END;
    }
    RSA_meth_set_priv_dec(tee_rsa_method, secure_rsa_priv_dec); // decrypt / key exchange
    RSA_meth_set_priv_enc(tee_rsa_method, secure_rsa_priv_enc); // signing
    if (!ENGINE_set_RSA(engine, tee_rsa_method)) {
        ERR_print_errors_fp(stderr);
        goto END;
    }

    // Only set the load private key function - don't override RSA methods
    if (!ENGINE_set_load_privkey_function(engine, __tee_load_privkey)) {
        ERR_print_errors_fp(stderr);
        goto END;
    }

    ENGINE_add(engine);
    ret = 0;
END:
    ENGINE_free(engine);
    return ret;
}