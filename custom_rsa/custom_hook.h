#ifndef __CUSTOM_HOOK_H__
#define __CUSTOM_HOOK_H__

#include <openssl/rsa.h>

RSA* create_custom_secure_rsa_key(const char* key_file);

int init_test_rsa_key(const char* key_file);

int secure_get_public_key_modulus(unsigned char* modulus, int* modulus_len);
int secure_get_public_key_exponent(unsigned char* exponent, int* exponent_len);

int secure_rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
int secure_rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding);
#endif