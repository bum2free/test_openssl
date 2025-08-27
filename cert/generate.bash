#!/bin/bash

# Generate the CA private key
openssl genrsa -out ca.key 2048

# Generate the CA certificate
openssl req -new -x509 -key ca.key -out ca.crt -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=My CA"

# Generate the server private key
openssl genrsa -out server.key 2048

# Generate the server certificate signing request (CSR)
openssl req -new -key server.key -out server.csr -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=My Server"

# Sign the server CSR with the CA certificate and key to generate the server certificate
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Generate the client private key
openssl genrsa -out client.key 2048

# Generate the client certificate signing request (CSR)
openssl req -new -key client.key -out client.csr -subj "/C=US/ST=CA/L=San Francisco/O=My Company/CN=My Client"

# Sign the client CSR with the CA certificate and key to generate the client certificate
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
