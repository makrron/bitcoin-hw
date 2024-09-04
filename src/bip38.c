#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <libscrypt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "base58.h"
#include "publicKey.h"
#include "privateKey.h"
#include "pk2hash.h"
#include "hex_bytes.h"
#include "generateAddress.h"
#include <openssl/ripemd.h>
#include <stdint.h>

// Base58 alphabet
static const char* BASE58_ALPHABET_BIP = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Función para convertir un array de bytes en Base58
char* encode_base58_bip(const unsigned char* input, size_t input_len) {
    int zero_count = 0;
    while (zero_count < input_len && input[zero_count] == 0) {
        ++zero_count;
    }

    // Estimación de tamaño máximo para el resultado
    size_t size = input_len * 138 / 100 + 1;  // Ajustado para el tamaño máximo de Base58
    unsigned char* buffer = (unsigned char*)malloc(size);
    memset(buffer, 0, size);

    // Proceso de conversión
    for (size_t i = zero_count; i < input_len; i++) {
        int carry = input[i];
        for (ssize_t j = size - 1; j >= 0; j--) {
            carry += 256 * buffer[j];
            buffer[j] = carry % 58;
            carry /= 58;
        }
    }

    // Saltar ceros iniciales
    int it = 0;
    while (it < size && buffer[it] == 0) {
        ++it;
    }

    // Convertir a Base58
    size_t result_size = zero_count + (size - it);
    char* result = (char*)malloc(result_size + 1);
    memset(result, '1', zero_count);  // Agregar prefijos de '1' para ceros iniciales en la entrada

    for (size_t i = zero_count; i < result_size; i++) {
        result[i] = BASE58_ALPHABET_BIP[buffer[it++]];
    }
    result[result_size] = '\0';

    free(buffer);
    return result;
}

// Función para realizar el hash SHA256 dos veces y obtener los primeros 4 bytes
void double_sha256_first4(const char *addr, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char hash2[SHA256_DIGEST_LENGTH];

    // Perform the first SHA256 hash
    SHA256((unsigned char *)addr, strlen(addr), hash1);

    // Perform the second SHA256 hash
    SHA256(hash1, SHA256_DIGEST_LENGTH, hash2);

    // Copy the first 4 bytes of the second hash to the output
    memcpy(output, hash2, 4);
}

// Función para realizar el hash SHA256 dos veces
void double_sha256(const unsigned char *input, size_t len, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(input, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, output);
}

// Función para convertir hexadecimal a bytes
int hex_to_bytes_bip(const char* hex, unsigned char* bytes, size_t bytes_len) {
    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
    return 1;
}

// Función para convertir bytes a hexadecimal
char* bytes_to_hex_bip(const unsigned char* bytes, size_t len) {
    char* hex = (char*)malloc(len * 2 + 1);
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

// Función para calcular RIPEMD160(SHA256(input))
void hash160(const unsigned char *input, size_t input_len, unsigned char *output) {
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(input, input_len, sha256_hash);
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, output);
}

// Generar dirección P2PKH a partir del hash160
char* generate_p2pkh_address(const unsigned char *pubkey_hash, int is_testnet) {
    unsigned char address[25];
    unsigned char checksum[SHA256_DIGEST_LENGTH];
    unsigned char double_sha[SHA256_DIGEST_LENGTH];

    // Prefijo para testnet o mainnet
    address[0] = is_testnet ? 0x6F : 0x00; // 0x6F para testnet, 0x00 para mainnet

    // Copiar pubkey_hash (20 bytes) después del prefijo
    memcpy(address + 1, pubkey_hash, 20);

    // Realizar el doble SHA256 para calcular el checksum
    SHA256(address, 21, double_sha);
    SHA256(double_sha, SHA256_DIGEST_LENGTH, checksum);

    // Copiar los primeros 4 bytes del checksum al final de la dirección
    memcpy(address + 21, checksum, 4);

    // Convertir la dirección a formato Base58Check
    char* base58_address = encode_base58_bip(address, 25);
    return base58_address;
}

// Función para cifrar una clave privada en formato BIP38 sin multiplicación EC
char* bip38_encrypt(const char* privkey_hex, const char* passphrase) {
    // Convertir la clave privada de formato hexadecimal a bytes.
    unsigned char privkey_bytes[32];
    if (!hex_to_bytes_bip(privkey_hex, privkey_bytes, 32)) {
        fprintf(stderr, "Error al convertir la clave privada de hexadecimal a bytes\n");
        return NULL;
    }

    // Derivar la clave pública a partir de la clave privada.
    unsigned char pubkey[65];
    size_t pubkey_len = sizeof(pubkey);
    if (!generate_uncompress_public_key_from_hex(privkey_hex, pubkey, &pubkey_len)) {
        fprintf(stderr, "Error al generar la clave pública\n");
        return NULL;
    }

    // Calcular el hash160 de la clave pública
    unsigned char pubkey_hash[RIPEMD160_DIGEST_LENGTH];
    hash160(pubkey, pubkey_len, pubkey_hash);

    // Generar dirección P2PKH (para testnet, puedes cambiar a 0 para mainnet)
    char* address = generate_p2pkh_address(pubkey_hash, 0);
    if (!address) {
        fprintf(stderr, "Error al generar la dirección P2PKH\n");
        return NULL;
    }
    /*
    printf("Public Key (uncompressed): ");
    for (size_t i = 0; i < pubkey_len; i++) {
        printf("%02x", pubkey[i]);
    }
    printf("\n");*/

    //printf("Dirección P2PKH: %s\n", address);

    // Obtener los primeros 4 bytes del doble hash SHA256 de la dirección
    unsigned char addresshash[4];
    double_sha256_first4(address, addresshash); // Aplicar hash SHA256 dos veces y obtener los primeros 4 bytes

    // Print the addresshash value
    /*printf("Address Hash: ");
    for (size_t i = 0; i < sizeof(addresshash); i++) {
        printf("%02x", addresshash[i]);
    }
    printf("\n");*/

    // Derivar la clave utilizando scrypt
    unsigned char derived_key[64];
    int scrypt_result = libscrypt_scrypt((const uint8_t*)passphrase, strlen(passphrase),
                                         addresshash, sizeof(addresshash),
                                         16384, 8, 8, derived_key, 64);
    if (scrypt_result != 0) {
        fprintf(stderr, "Error en la derivación de clave con scrypt\n");
        free(address);
        return NULL;
    }

    unsigned char derivedhalf1[32], derivedhalf2[32];
    memcpy(derivedhalf1, derived_key, 32);
    memcpy(derivedhalf2, derived_key + 32, 32);

    // Cifrar la clave privada con AES-256 utilizando derivedhalf2 en modo ECB
    AES_KEY aes_encrypt_key;
    AES_set_encrypt_key(derivedhalf2, 256, &aes_encrypt_key);

    unsigned char encryptedhalf1[16], encryptedhalf2[16];
    unsigned char temp1[16], temp2[16];

    // Aplicar XOR entre la primera mitad de la clave privada y derivedhalf1 antes del cifrado
    for (int i = 0; i < 16; i++) {
        temp1[i] = privkey_bytes[i] ^ derivedhalf1[i];
    }

    AES_ecb_encrypt(temp1, encryptedhalf1, &aes_encrypt_key, AES_ENCRYPT);

    // Aplicar XOR entre la segunda mitad de la clave privada y derivedhalf1 antes del cifrado
    for (int i = 0; i < 16; i++) {
        temp2[i] = privkey_bytes[i + 16] ^ derivedhalf1[i + 16];
    }

    AES_ecb_encrypt(temp2, encryptedhalf2, &aes_encrypt_key, AES_ENCRYPT);

    // Construir el formato final del BIP38
    unsigned char encrypted_privkey[43];  // Cambié a 43 para incluir el checksum
    encrypted_privkey[0] = 0x01;   // Versión del BIP38
    encrypted_privkey[1] = 0x42;   // Indica ausencia de multiplicación EC
    encrypted_privkey[2] = 0xc0;   // Byte de flag para clave sin compresión

    memcpy(&encrypted_privkey[3], addresshash, 4);  // Agregar hash de la dirección
    memcpy(&encrypted_privkey[7], encryptedhalf1, 16);
    memcpy(&encrypted_privkey[23], encryptedhalf2, 16);

    // Añadir el checksum al final
    unsigned char checksum[4];
    double_sha256(encrypted_privkey, 39, checksum);  // Cambié 39 para el tamaño correcto
    memcpy(&encrypted_privkey[39], checksum, 4);     // Adjuntar el checksum a los 39 bytes previos

    // Codificar la clave cifrada en Base58Check
    char* bip38_key = encode_base58_bip(encrypted_privkey, 43);

    free(address); // Liberar memoria de la dirección
    return bip38_key;
}

int main() {
    // Clave privada en formato hexadecimal
    const char* privkey_hex = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE";

    // Frase de contraseña para cifrar la clave
    const char* passphrase = "TestingOneTwoThree";

    // Cifrar la clave privada en formato BIP38
    char* encrypted_privkey = bip38_encrypt(privkey_hex, passphrase);

    if (encrypted_privkey != NULL) {
        // Mostrar la clave privada cifrada
        printf("Clave privada cifrada (BIP38): %s\n", encrypted_privkey);
        free(encrypted_privkey); // Liberar memoria utilizada
    } else {
        printf("Fallo al cifrar la clave privada.\n");
    }

    return 0;
}