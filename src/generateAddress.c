#include "generateAddress.h"
#include "base58.h"
#include "hex_bytes.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char* P2PKH_address(const char* public_key_hash_hex, int network) {
    //printf("Generating address...\n");
    //printf("Public Key Hash: %s\n", public_key_hash_hex);

    unsigned char address[25]; // 1 byte for prefix + 20 bytes for public key hash + 4 bytes for checksum
    char* output = malloc(50); // Ajustar según la necesidad del tamaño de la salida de base58
    if (!output) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    // Convert hex string to binary
    unsigned char public_key_hash[20];
    hex_to_bytes(public_key_hash_hex, public_key_hash, sizeof(public_key_hash));

    // Set prefix based on network: 0x00 for Mainnet, 0x6f for Testnet
    address[0] = (network == 0) ? 0x00 : 0x6f;
    memcpy(address + 1, public_key_hash, 20); // Copy the public key hash into the address buffer after the prefix

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(address, 21, hash); // Hash the first 21 bytes of the address
    SHA256(hash, SHA256_DIGEST_LENGTH, hash); // Hash the hash to get the checksum

    // Copy first 4 bytes of the result into the last 4 bytes of the address array for checksum
    memcpy(address + 21, hash, 4);

    //printf("Checksum: ");
    //for (int i = 0; i < 4; i++) {
    //    printf("%02x", hash[i]);
    //}
    //printf("\n");

    // Convert address (now full 25-byte array) to a hexadecimal string for Base58 encoding
    char* hex; // Each byte can be up to 2 hex characters
    hex = bytes_to_hex(address, 25);

    // Base58 encoding of the address
    encode_base58(hex, output); // Assuming encode_base58 is corrected to use this hex input

    free(hex);

    return output;
}

