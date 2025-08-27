#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 30505

#define CERT_FILE "server.crt"
#define KEY_FILE "server.key"
#define CA_FILE "ca.crt"


int main(int argc, char* argv[]) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Default values
    std::string key_file = KEY_FILE;
    std::string cert_file = CERT_FILE;
    std::string ca_file = CA_FILE;
    int port = PORT;

    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--ca") == 0 && i + 1 < argc) {
            ca_file = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = std::atoi(argv[++i]);
        } else {
            std::cerr << "Unknown or incomplete argument: " << argv[i] << std::endl;
        }
    }

    // Print out all parameters
    std::cout << "Parameters:" << std::endl;
    std::cout << "  --key  " << key_file << std::endl;
    std::cout << "  --cert " << cert_file << std::endl;
    std::cout << "  --ca   " << ca_file << std::endl;
    std::cout << "  --port " << port << std::endl;

    SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL context" << std::endl;
        return 1;
    }
    SSL_CTX_set_ecdh_auto(ctx, 1);
    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load server certificate" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Failed to load server private key" << std::endl;
        return 1;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        std::cerr << "Private key does not match the certificate public key" << std::endl;
        return 1;
    }
    if (SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), NULL) <= 0) {
        std::cerr << "Failed to load CA certificate" << std::endl;
        return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        std::cerr << "Failed to set socket options" << std::endl;
        return 1;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        std::cerr << "Failed to bind socket" << std::endl;
        return 1;
    }

    if (listen(server_fd, 3) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << port << std::endl;

    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
        std::cerr << "Failed to accept incoming connection" << std::endl;
        return 1;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, new_socket);
    if (SSL_accept(ssl) <= 0) {
        std::cerr << "Failed to establish SSL connection" << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char buffer[1024] = {0};
    int valread = SSL_read(ssl, buffer, sizeof(buffer));
    std::cout << "Received message: " << buffer << std::endl;

    const char* response = "Hello from server";
    SSL_write(ssl, response, strlen(response));

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}
