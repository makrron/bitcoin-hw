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

// Función para realizar el hash SHA256 dos veces
void double_sha256(const unsigned char *input, size_t len, unsigned char *output) {
    unsigned char hash1[SHA256_DIGEST_LENGTH];
    SHA256(input, len, hash1);
    SHA256(hash1, SHA256_DIGEST_LENGTH, output);
}

// Función para cifrar una clave privada en formato BIP38 sin multiplicación EC
char* bip38_encrypt(const char* privkey_hex, const char* passphrase) {
    // Convertir la clave privada de formato hexadecimal a bytes.
    unsigned char privkey_bytes[32];
    if (!hex_to_bytes(privkey_hex, privkey_bytes, 32)) {
        fprintf(stderr, "Fallo al convertir la clave privada de hexadecimal a bytes\n");
        return NULL;
    }

    // Derivar la clave pública a partir de la clave privada.
    unsigned char pubkey[33];
    size_t pubkey_len = sizeof(pubkey);
    generate_public_key_from_hex(privkey_hex, pubkey, &pubkey_len);

    // Realizar hash de la clave pública para obtener la dirección (P2PKH).
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256(pubkey, pubkey_len, sha256_hash);

    unsigned char ripemd160_hash[RIPEMD160_DIGEST_LENGTH];
    RIPEMD160(sha256_hash, SHA256_DIGEST_LENGTH, ripemd160_hash);

    // Convertir el hash a una representación en hexadecimal
    char pubkey_hash_hex[41];
    for (int i = 0; i < RIPEMD160_DIGEST_LENGTH; i++) {
        snprintf(pubkey_hash_hex + (i * 2), 3, "%02x", ripemd160_hash[i]);
    }

    // Generar la dirección P2PKH
    char* address_str = (char*) malloc(35);  // Reservar suficiente espacio
    strcpy(address_str, P2PKH_address(pubkey_hash_hex, 0));  // Copiar la dirección generada

    // Realizar hash de la dirección P2PKH para el cifrado BIP38
    unsigned char address[25];
    hex_to_bytes(address_str, address, sizeof(address));

    // Obtener los primeros 4 bytes del doble hash SHA256 de la dirección
    unsigned char addresshash[4];
    double_sha256(address, 20, addresshash); // Aplicar hash SHA256 dos veces

    // Derivar la clave utilizando scrypt
    unsigned char derived_key[64];
    int scrypt_result = libscrypt_scrypt((const uint8_t*)passphrase, strlen(passphrase),
                                         addresshash, sizeof(addresshash),
                                         16384, 8, 8, derived_key, 64);
    if (scrypt_result != 0) {
        fprintf(stderr, "Error en la derivación de clave con scrypt\n");
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
    unsigned char encrypted_privkey[39];
    encrypted_privkey[0] = 0x01;   // Versión del BIP38
    encrypted_privkey[1] = 0x42;   // Indica ausencia de multiplicación EC
    encrypted_privkey[2] = 0xc0;   // Byte de flag para clave sin compresión

    memcpy(&encrypted_privkey[3], addresshash, 4);  // Agregar hash de la dirección
    memcpy(&encrypted_privkey[7], encryptedhalf1, 16);
    memcpy(&encrypted_privkey[23], encryptedhalf2, 16);

    // Añadir el checksum al final
    unsigned char checksum[4];
    double_sha256(encrypted_privkey, 39, checksum);
    memcpy(&encrypted_privkey[39], checksum, 4);

    // Convertir el arreglo de bytes `encrypted_privkey` a formato hexadecimal
    char* encrypted_privkey_hex = bytes_to_hex(encrypted_privkey, 43);  // 39 + 4 bytes de checksum

    // Codificar la clave cifrada en Base58Check
    char* bip38_key = (char*) malloc(100);  // Reservar suficiente espacio
    encode_base58(encrypted_privkey_hex, bip38_key);

    free(address_str); // Liberar memoria utilizada
    free(encrypted_privkey_hex); // Liberar cadena hexadecimal
    return bip38_key;
}

int main() {
    // Clave privada en formato hexadecimal
    const char* privkey_hex = "09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE";

    // Frase de contraseña para cifrar la clave
    const char* passphrase = "Satoshi";

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
