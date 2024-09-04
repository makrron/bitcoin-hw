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

// Función para hacer hash SHA256 dos veces
void double_sha256(const unsigned char *input, size_t len, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(input, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, output);
}

// Función para cifrar una clave privada con BIP38 sin EC multiplicación
char* bip38_encrypt(const char* privkey_hex, const char* passphrase) {
    // 1. Convertir la clave privada de hexadecimal a bytes.
    unsigned char privkey_bytes[32];
    if (!hex_to_bytes(privkey_hex, privkey_bytes, 32)) {
        fprintf(stderr, "Error al convertir la clave privada hex a bytes\n");
        return NULL;
    }

    // 2. Obtener la clave pública a partir de la clave privada.
    unsigned char pubkey[33];
    size_t pubkey_len = sizeof(pubkey);
    generate_public_key_from_hex(privkey_hex, pubkey, &pubkey_len);

    // 3. Hash de la clave pública para obtener la dirección (P2PKH).
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, pubkey_len, sha256_hash);

    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

    // Convertir el hash a formato hexadecimal
    char pubkey_hash_hex[41];
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        snprintf(pubkey_hash_hex + (i * 2), 3, "%02x", ripemd160_hash[i]);
    }

    // Generar la dirección P2PKH
    char* address_str = (char*) malloc(35);  // Asegúrate de que sea lo suficientemente grande
    strcpy(address_str, P2PKH_address(pubkey_hash_hex, 0));  // Copiar el valor de la dirección

    // 4. Hash de la dirección P2PKH para BIP38
    unsigned char address[25];
    hex_to_bytes(address_str, address, sizeof(address));

    // 5. Obtener los primeros 4 bytes del SHA256 doble de la dirección
    unsigned char addresshash[4];
    double_sha256(address, 20, addresshash); // Hash SHA256 dos veces

    // 6. Derivar la clave con scrypt
    unsigned char derived_key[64];
    int scrypt_result = libscrypt_scrypt((const uint8_t*)passphrase, strlen(passphrase),
                                         addresshash, sizeof(addresshash),
                                         16384, 8, 8, derived_key, 64);
    if (scrypt_result != 0) {
        fprintf(stderr, "Error al derivar clave con scrypt\n");
        return NULL;
    }

    unsigned char derivedhalf1[32], derivedhalf2[32];
    memcpy(derivedhalf1, derived_key, 32);
    memcpy(derivedhalf2, derived_key + 32, 32);

    // 7. Cifrar la clave privada con AES-256 usando derivedhalf2 en modo ECB
    AES_KEY aes_encrypt_key;
    AES_set_encrypt_key(derivedhalf2, 256, &aes_encrypt_key);

    unsigned char encryptedhalf1[16], encryptedhalf2[16];
    unsigned char temp1[16], temp2[16];

    // XOR entre la primera mitad de la clave privada y derivedhalf1 antes de cifrar
    for (int i = 0; i < 16; i++) {
        temp1[i] = privkey_bytes[i] ^ derivedhalf1[i];
    }

    AES_ecb_encrypt(temp1, encryptedhalf1, &aes_encrypt_key, AES_ENCRYPT);

    // XOR entre la segunda mitad de la clave privada y derivedhalf1 antes de cifrar
    for (int i = 0; i < 16; i++) {
        temp2[i] = privkey_bytes[i + 16] ^ derivedhalf1[i + 16];
    }

    AES_ecb_encrypt(temp2, encryptedhalf2, &aes_encrypt_key, AES_ENCRYPT);

    // 8. Formato final del BIP38
    unsigned char encrypted_privkey[39];
    encrypted_privkey[0] = 0x01;   // BIP38 versión
    encrypted_privkey[1] = 0x42;   // Indica que no usa EC multiply
    encrypted_privkey[2] = 0xc0;   // Flag byte, clave sin compresión

    memcpy(&encrypted_privkey[3], addresshash, 4);  // Hash de la dirección
    memcpy(&encrypted_privkey[7], encryptedhalf1, 16);
    memcpy(&encrypted_privkey[23], encryptedhalf2, 16);

    // 9. Añadir el checksum
    unsigned char checksum[4];
    double_sha256(encrypted_privkey, 39, checksum);
    memcpy(&encrypted_privkey[39], checksum, 4);

    // 10. Convertir el arreglo de bytes `encrypted_privkey` a cadena hexadecimal
    char* encrypted_privkey_hex = bytes_to_hex(encrypted_privkey, 43);  // 39 + 4 bytes de checksum

    // 11. Codificar en Base58Check
    char* bip38_key = (char*) malloc(100);  // Asegúrate de que sea suficientemente grande
    encode_base58(encrypted_privkey_hex, bip38_key);

    free(address_str); // Liberar memoria
    free(encrypted_privkey_hex); // Liberar la cadena hexadecimal
    return bip38_key;
}

int main() {
    // Clave privada en formato hexadecimal
    const char* privkey_hex = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE";

    // Passphrase para cifrar la clave
    const char* passphrase = "Satoshi";

    // cifrar la clave privada con BIP38
    char* encrypted_privkey = bip38_encrypt(privkey_hex, passphrase);

    if (encrypted_privkey != NULL) {
        // Imprimir la clave privada cifrada
        printf("Clave privada cifrada (BIP38): %s\n", encrypted_privkey);
        free(encrypted_privkey); // Liberar la memoria
    } else {
        printf("Error al cifrar la clave privada.\n");
    }

    return 0;
}
