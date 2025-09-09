#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/engine.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "custom_engine.h"

static const char *engine_id = "test_engine";
static const char *engine_name = "Custom TEE Engine for RSA (Test)";

int main(int argc, char* argv[]) {
    int client_fd;
    struct sockaddr_in address;

    // Default file paths
    const char* cert_file = "client.crt";
    const char* key_file = "client.key";
    const char* ca_file = "ca.crt";

    // Default remote address
    const char* remote_ip = "127.0.0.1";
    int remote_port = 30505;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "--remote") == 0 && i + 1 < argc) {
            // Parse ip:port
            const char* arg = argv[++i];
            const char* colon = strchr(arg, ':');
            if (colon) {
                size_t ip_len = colon - arg;
                char* ip_buf = new char[ip_len + 1];
                strncpy(ip_buf, arg, ip_len);
                ip_buf[ip_len] = '\0';
                remote_ip = ip_buf;
                remote_port = atoi(colon + 1);
            } else {
                remote_ip = arg;
            }
        }
    }
    // Print all parameters
    std::cout << "Parameters:" << std::endl;
    std::cout << "  --cert   " << cert_file << std::endl;
    std::cout << "  --key    " << key_file << std::endl;
    std::cout << "  --ca     " << ca_file << std::endl;
    std::cout << "  --remote " << remote_ip << ":" << remote_port << std::endl;

/////////////////////////////////////////////////////////////////////////////
    if (create_custom_engine(engine_id, engine_name, key_file) != 0) {
        std::cerr << "Failed to create custom engine" << std::endl;
        return 1;
    }

    ENGINE *eng = ENGINE_by_id(engine_id);
    if(!eng) {
        std::cerr << "Failed to load TEE engine" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    } else {
        std::cout << "Successfully loaded TEE engine" << std::endl;
    }

    if(!ENGINE_init(eng)) {
        std::cerr << "Failed to initialize TEE engine" << std::endl;
        ERR_print_errors_fp(stderr);
        ENGINE_free(eng);
        return 1;
    } else {
        std::cout << "Successfully initialized TEE engine" << std::endl;
    }
/////////////////////////////////////////////////////////////////////////////
    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
        return 1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_cipher_list(ctx, "DEFAULT:!ECDH");

    SSL_CTX_set_ecdh_auto(ctx, 1);

    //read cert file to a buffer and load it to ctx; the cert file is in PEM format
    {
        FILE* fp = fopen(cert_file, "r");
        if (!fp) {
            std::cerr << "Failed to open cert file" << std::endl;
            return 1;
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        rewind(fp);
        char* cert = (char*)malloc(size + 1);
        if (!cert) {
            std::cerr << "Failed to allocate memory" << std::endl;
            return 1;
        }
        fread(cert, 1, size, fp);
        cert[size] = '\0';
        fclose(fp);

        BIO* bio = BIO_new_mem_buf(cert, -1);
        if (!bio) {
            std::cerr << "Failed to create BIO" << std::endl;
            return 1;
        }
        X509* x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if (!x509) {
            std::cerr << "Failed to parse certificate" << std::endl;
            return 1;
        }
        if (SSL_CTX_use_certificate(ctx, x509) <= 0) {
            std::cerr << "Failed to load client certificate" << std::endl;
            return 1;
        }
        free(cert);
        BIO_free(bio);
    }
    //read key file to a buffer and load it to ctx; the key file is in PEM format
    {
#if 1
    EVP_PKEY *pkey = ENGINE_load_private_key(eng, "key id not used", NULL, NULL);
    if(!pkey) {
        std::cerr << "Failed to load private key from TEE engine" << std::endl;
        ERR_print_errors_fp(stderr);
        ENGINE_finish(eng);
        ENGINE_free(eng);
        return 1;
    } else {
        std::cout << "Successfully loaded private key from TEE engine" << std::endl;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        std::cerr << "Failed to set server private key from TEE engine" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        ENGINE_finish(eng);
        ENGINE_free(eng);
        return 1;
    }
    EVP_PKEY_free(pkey);
#else
        FILE* fp = fopen(key_file, "r");
        if (!fp) {
            std::cerr << "Failed to open key file" << std::endl;
            return 1;
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        rewind(fp);
        char* key = (char*)malloc(size + 1);
        if (!key) {
            std::cerr << "Failed to allocate memory" << std::endl;
            return 1;
        }
        fread(key, 1, size, fp);
        key[size] = '\0';
        fclose(fp);

        BIO* bio = BIO_new_mem_buf(key, -1);
        if (!bio) {
            std::cerr << "Failed to create BIO" << std::endl;
            return 1;
        }
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
        if (!pkey) {
            std::cerr << "Failed to parse private key" << std::endl;
            return 1;
        }
        if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
            std::cerr << "Failed to load client private key" << std::endl;
            return 1;
        }
        free(key);
        BIO_free(bio);
#endif
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        return 1;
    }

    //read ca file to a buffer and load it to ctx; the ca file is in PEM format
    {
        FILE* fp = fopen(ca_file, "r");
        if (!fp) {
            std::cerr << "Failed to open CA file" << std::endl;
            return 1;
        }
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        rewind(fp);
        char* ca = (char*)malloc(size + 1);
        if (!ca) {
            std::cerr << "Failed to allocate memory" << std::endl;
            return 1;
        }
        fread(ca, 1, size, fp);
        ca[size] = '\0';
        fclose(fp);

        BIO* bio = BIO_new_mem_buf(ca, -1);
        if (!bio) {
            std::cerr << "Failed to create BIO" << std::endl;
            return 1;
        }
        X509* x509 = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if (!x509) {
            std::cerr << "Failed to parse CA certificate" << std::endl;
            return 1;
        }
        X509_STORE* store = SSL_CTX_get_cert_store(ctx);
        if (!store) {
            std::cerr << "Failed to get cert store" << std::endl;
            return 1;
        }
        if (X509_STORE_add_cert(store, x509) <= 0) {
            std::cerr << "Failed to add CA certificate to cert store" << std::endl;
            return 1;
        }
        free(ca);
        BIO_free(bio);
    }

    /*
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load client certificate" << std::endl;
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load client private key" << std::endl;
        return 1;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        return 1;
    }

    if (SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL) <= 0) {
        std::cerr << "Failed to load CA certificate" << std::endl;
        return 1;
    }
*/
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(remote_port);

    if (inet_pton(AF_INET, remote_ip, &address.sin_addr) <= 0) {
        std::cerr << "Invalid address: " << remote_ip << std::endl;
        return 1;
    }

    if (connect(client_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Failed to connect to server" << std::endl;
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_connect(ssl) <= 0) {
        std::cerr << "Failed to establish SSL connection" << std::endl;
		ERR_print_errors_fp (stderr);
        return 1;
    }

    const char* message = "Hello from client";
    //send(client_fd, message, strlen(message), 0);
	SSL_write(ssl, message, strlen(message));

    char buffer[1024] = {0};
    //int valread = read(client_fd, buffer, sizeof(buffer));
	int valread = SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Received message: " << buffer << std::endl;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    SSL_CTX_free(ctx);

    return 0;
}
