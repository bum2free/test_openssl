#include <iostream>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "custom_hook.h"

static RSA* test_rsa_key = nullptr; // Global test RSA key for callbacks

// Initialize test RSA key from file (for testing purposes)
int init_test_rsa_key(const char* key_file) {
    FILE* fp = fopen(key_file, "r");
    if (!fp) {
        std::cerr << "Failed to open test key file: " << key_file << std::endl;
        return 0;
    }
    
    test_rsa_key = RSA_new();
    if (!test_rsa_key) {
        std::cerr << "Failed to create test RSA key" << std::endl;
        fclose(fp);
        return 0;
    }
    
    // Read the private key from file
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    
    if (!pkey) {
        std::cerr << "Failed to read private key from file" << std::endl;
        RSA_free(test_rsa_key);
        test_rsa_key = nullptr;
        return 0;
    }
    
    RSA* file_rsa = EVP_PKEY_get1_RSA(pkey);
    EVP_PKEY_free(pkey);
    
    if (!file_rsa) {
        std::cerr << "Failed to extract RSA key from EVP_PKEY" << std::endl;
        RSA_free(test_rsa_key);
        test_rsa_key = nullptr;
        return 0;
    }
    
    // Copy the key components
    const BIGNUM *n, *e, *d;
    RSA_get0_key(file_rsa, &n, &e, &d);
    
    BIGNUM *new_n = BN_dup(n);
    BIGNUM *new_e = BN_dup(e);
    BIGNUM *new_d = BN_dup(d);
    
    RSA_set0_key(test_rsa_key, new_n, new_e, new_d);
    
    // Copy other components if they exist
    const BIGNUM *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_factors(file_rsa, &p, &q);
    RSA_get0_crt_params(file_rsa, &dmp1, &dmq1, &iqmp);
    
    if (p && q) {
        RSA_set0_factors(test_rsa_key, BN_dup(p), BN_dup(q));
    }
    if (dmp1 && dmq1 && iqmp) {
        RSA_set0_crt_params(test_rsa_key, BN_dup(dmp1), BN_dup(dmq1), BN_dup(iqmp));
    }
    
    RSA_free(file_rsa);
    std::cerr << "Test RSA key initialized successfully" << std::endl;
    return 1;
}

// Test implementations using OpenSSL's default RSA operations
static int __secure_rsa_decrypt(const unsigned char* encrypted_data, int encrypted_len,
                      unsigned char* decrypted_data, int* decrypted_len) {
    std::cerr << "secure_rsa_decrypt called with " << encrypted_len << " bytes" << std::endl;
    
    if (!test_rsa_key) {
        std::cerr << "Test RSA key not initialized" << std::endl;
        return 0;
    }
    
    // Use OpenSSL's default private decrypt for testing
    int result = RSA_private_decrypt(encrypted_len, encrypted_data, decrypted_data, 
                                   test_rsa_key, RSA_PKCS1_PADDING);
    if (result > 0) {
        *decrypted_len = result;
        std::cerr << "secure_rsa_decrypt successful, decrypted " << result << " bytes" << std::endl;
        return 1;
    } else {
        std::cerr << "secure_rsa_decrypt failed" << std::endl;
        ERR_print_errors_fp(stderr);
        return 0;
    }
}

static int __secure_rsa_sign(const unsigned char* digest, int digest_len,
                   unsigned char* signature, int* signature_len, int padding) {
    std::cerr << "secure_rsa_sign called with " << digest_len << " bytes" << std::endl;
    
    if (!test_rsa_key) {
        std::cerr << "Test RSA key not initialized" << std::endl;
        return 0;
    }
    
    // Use OpenSSL's default private encrypt (signing) for testing
    int result = RSA_private_encrypt(digest_len, digest, signature, 
                                   test_rsa_key, padding);
    if (result > 0) {
        *signature_len = result;
        std::cerr << "secure_rsa_sign successful, signature " << result << " bytes" << std::endl;
        return 1;
    } else {
        std::cerr << "secure_rsa_sign failed" << std::endl;
        ERR_print_errors_fp(stderr);
        return 0;
    }
}

int secure_get_public_key_modulus(unsigned char* modulus, int* modulus_len) {
    if (!test_rsa_key) {
        std::cerr << "Test RSA key not initialized" << std::endl;
        return 0;
    }
    
    const BIGNUM* n = nullptr;
    RSA_get0_key(test_rsa_key, &n, nullptr, nullptr);
    
    if (!n) {
        std::cerr << "Failed to get modulus from test key" << std::endl;
        return 0;
    }
    
    int len = BN_bn2bin(n, modulus);
    *modulus_len = len;
    std::cerr << "Retrieved modulus: " << len << " bytes" << std::endl;
    return 1;
}

int secure_get_public_key_exponent(unsigned char* exponent, int* exponent_len) {
    if (!test_rsa_key) {
        std::cerr << "Test RSA key not initialized" << std::endl;
        return 0;
    }
    
    const BIGNUM* e = nullptr;
    RSA_get0_key(test_rsa_key, nullptr, &e, nullptr);
    
    if (!e) {
        std::cerr << "Failed to get exponent from test key" << std::endl;
        return 0;
    }
    
    int len = BN_bn2bin(e, exponent);
    *exponent_len = len;
    std::cerr << "Retrieved exponent: " << len << " bytes" << std::endl;
    return 1;
}

// Custom RSA method callbacks
int secure_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to,
                              RSA *rsa, int padding) {
    std::cerr << "secure_rsa_priv_enc called with padding: " << padding << std::endl;
    
    // Handle different padding types that TLS might use
    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING) {
        std::cerr << "Unsupported padding type: " << padding << std::endl;
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_ENCRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }

    int signature_len = RSA_size(rsa);
    int result = __secure_rsa_sign(from, flen, to, &signature_len, padding);
    
    return result ? signature_len : -1;
}

int secure_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to,
                              RSA *rsa, int padding) {
    std::cerr << "secure_rsa_priv_dec called with padding: " << padding << std::endl;
    
    // Handle different padding types
    if (padding != RSA_PKCS1_PADDING && padding != RSA_NO_PADDING) {
        std::cerr << "Unsupported padding type: " << padding << std::endl;
        RSAerr(RSA_F_RSA_OSSL_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
        return -1;
    }
    
    // For testing, use the default OpenSSL implementation directly
    const RSA_METHOD* default_method = RSA_PKCS1_OpenSSL();
    int (*default_priv_dec)(int, const unsigned char *, unsigned char *, RSA *, int) = 
        RSA_meth_get_priv_dec(default_method);
    
    if (default_priv_dec) {
        // Temporarily use the test key with default method
        return default_priv_dec(flen, from, to, test_rsa_key, padding);
    }
    
    return -1;
}

static RSA_METHOD* __create_secure_rsa_method() {
    RSA_METHOD* method = RSA_meth_new("Secure RSA", RSA_METHOD_FLAG_NO_CHECK);
    if (!method) {
        return nullptr;
    }
    
    // Set the private key operations to use our secure functions
    RSA_meth_set_priv_enc(method, secure_rsa_priv_enc);
    RSA_meth_set_priv_dec(method, secure_rsa_priv_dec);

    return method;
}

// Create RSA key with public components but secure private operations
RSA* create_custom_secure_rsa_key(const char* key_file) {
    if (!init_test_rsa_key(key_file)) {
        return nullptr;
    }
    
    RSA* rsa = RSA_new();
    if (!rsa) {
        return nullptr;
    }
    
    // Set the custom method
    RSA_METHOD* secure_method = __create_secure_rsa_method();
    if (!secure_method) {
        RSA_free(rsa);
        return nullptr;
    }
    
    RSA_set_method(rsa, secure_method);
    
    // Get public key components from secure storage
    unsigned char modulus_buf[512];  // Adjust size as needed
    unsigned char exponent_buf[8];   // Typically 3 bytes for 65537
    int modulus_len = sizeof(modulus_buf);
    int exponent_len = sizeof(exponent_buf);
    
    if (!secure_get_public_key_modulus(modulus_buf, &modulus_len) ||
        !secure_get_public_key_exponent(exponent_buf, &exponent_len)) {
        RSA_free(rsa);
        return nullptr;
    }
    
    // Create BIGNUMs for the public key components
    BIGNUM* n = BN_bin2bn(modulus_buf, modulus_len, nullptr);
    BIGNUM* e = BN_bin2bn(exponent_buf, exponent_len, nullptr);
    
    if (!n || !e) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    
    // Set the public key components (private key d is not set)
    if (!RSA_set0_key(rsa, n, e, nullptr)) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    
    return rsa;
}