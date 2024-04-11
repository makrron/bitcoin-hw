#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void publicKeytoHash(const char *data, char *output) {
    unsigned char sha256_digest[SHA256_DIGEST_LENGTH];
    unsigned char ripemd160_digest[RIPEMD160_DIGEST_LENGTH];

    // Convertir la data hexadecimal a bytes
    int data_len = strlen(data) / 2;
    unsigned char *data_bytes = (unsigned char *)malloc(data_len);
    for (int i = 0; i < data_len; i++) {
        sscanf(&data[i * 2], "%2hhx", &data_bytes[i]);
    }

    // SHA-256
    SHA256(data_bytes, data_len, sha256_digest);

    // RIPEMD-160
    RIPEMD160(sha256_digest, SHA256_DIGEST_LENGTH, ripemd160_digest);

    // Convertir el digest de RIPEMD-160 a hexadecimal
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        sprintf(&output[i * 2], "%02x", ripemd160_digest[i]);
    }

    //free(data_bytes);
}
