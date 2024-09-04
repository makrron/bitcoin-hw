#include <openssl/sha.h>
#include <openssl/aes.h>
#include <libscrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "publicKey.h"
#include "hex_bytes.h"
#include "base58.h"
#include <openssl/ripemd.h>
#include <stdint.h>


void double_sha256_first4(const char *addr, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)addr, strlen(addr), hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);
    memcpy(output, hash2, 4);
}

void double_sha256(const unsigned char *input, size_t len, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(input, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, output);
}

int hex_to_bytes_bip(const char* hex, unsigned char* bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
    return 1;
}

char* bytes_to_hex_bip(const unsigned char* bytes, size_t len) {
    char* hex = (char*)malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

void hash160(const unsigned char *input, size_t input_len, unsigned char *output) {
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(input, input_len, sha256_hash);
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, output);
}

char* generate_p2pkh_address(const unsigned char *pubkey_hash, int is_testnet) {
    unsigned char address[25], checksum[SHA256_DIGEST_LENGTH], double_sha[SHA256_DIGEST_LENGTH];
    address[0] = is_testnet ? 0x6F : 0x00;
    memcpy(address + 1, pubkey_hash, 20);
    SHA256(address, 21, double_sha);
    SHA256(double_sha, SHA256_DIGEST_LENGTH, checksum);
    memcpy(address + 21, checksum, 4);
    return encode_base58_bip(address, 25);
}

char* bip38_encrypt(const char* privkey_hex, const char* passphrase) {
    unsigned char privkey_bytes[32], pubkey[65], pubkey_hash[RIPEMD160_DIGEST_LENGTH], addresshash[4], derived_key[64], derivedhalf1[32], derivedhalf2[32], encryptedhalf1[16], encryptedhalf2[16], temp1[16], temp2[16], encrypted_privkey[43], checksum[4];
    size_t pubkey_len = sizeof(pubkey);

    if (!hex_to_bytes_bip(privkey_hex, privkey_bytes, 32) || !generate_uncompress_public_key_from_hex(privkey_hex, pubkey, &pubkey_len)) {
        fprintf(stderr, "Error al convertir la clave privada o generar la clave pública\n");
        return NULL;
    }

    hash160(pubkey, pubkey_len, pubkey_hash);
    char* address = generate_p2pkh_address(pubkey_hash, 0);
    if (!address) {
        fprintf(stderr, "Error al generar la dirección P2PKH\n");
        return NULL;
    }

    double_sha256_first4(address, addresshash);
    free(address);

    if (libscrypt_scrypt((const uint8_t*)passphrase, strlen(passphrase), addresshash, sizeof(addresshash), 16384, 8, 8, derived_key, 64) != 0) {
        fprintf(stderr, "Error en la derivación de clave con scrypt\n");
        return NULL;
    }

    memcpy(derivedhalf1, derived_key, 32);
    memcpy(derivedhalf2, derived_key + 32, 32);

    AES_KEY aes_encrypt_key;
    AES_set_encrypt_key(derivedhalf2, 256, &aes_encrypt_key);

    for (int i = 0; i < 16; i++) {
        temp1[i] = privkey_bytes[i] ^ derivedhalf1[i];
        temp2[i] = privkey_bytes[i + 16] ^ derivedhalf1[i + 16];
    }

    AES_ecb_encrypt(temp1, encryptedhalf1, &aes_encrypt_key, AES_ENCRYPT);
    AES_ecb_encrypt(temp2, encryptedhalf2, &aes_encrypt_key, AES_ENCRYPT);

    encrypted_privkey[0] = 0x01;
    encrypted_privkey[1] = 0x42;
    encrypted_privkey[2] = 0xc0;
    memcpy(&encrypted_privkey[3], addresshash, 4);
    memcpy(&encrypted_privkey[7], encryptedhalf1, 16);
    memcpy(&encrypted_privkey[23], encryptedhalf2, 16);

    double_sha256(encrypted_privkey, 39, checksum);
    memcpy(&encrypted_privkey[39], checksum, 4);

    return encode_base58_bip(encrypted_privkey, 43);
}

int main() {
    const char* privkey_hex = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE";
    const char* passphrase = "TestingOneTwoThree";
    char* encrypted_privkey = bip38_encrypt(privkey_hex, passphrase);

    if (encrypted_privkey != NULL) {
        printf("Clave privada cifrada (BIP38): %s\n", encrypted_privkey);
        free(encrypted_privkey);
    } else {
        printf("Fallo al cifrar la clave privada.\n");
    }

    return 0;
}