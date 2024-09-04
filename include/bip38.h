//
// Created by makrron on 4/09/24.
//

#ifndef BIP38_H
#define BIP38_H

#include <stddef.h>

// Función para realizar el hash SHA256 dos veces y obtener los primeros 4 bytes
void double_sha256_first4(const char *addr, unsigned char *output);

// Función para realizar el hash SHA256 dos veces
void double_sha256(const unsigned char *input, size_t len, unsigned char *output);

// Función para convertir hexadecimal a bytes
int hex_to_bytes_bip(const char* hex, unsigned char* bytes, size_t bytes_len);

// Función para convertir bytes a hexadecimal
char* bytes_to_hex_bip(const unsigned char* bytes, size_t len);

// Función para calcular RIPEMD160(SHA256(input))
void hash160(const unsigned char *input, size_t input_len, unsigned char *output);

// Generar dirección P2PKH a partir del hash160
char* generate_p2pkh_address(const unsigned char *pubkey_hash, int is_testnet);

// Función para cifrar una clave privada en formato BIP38 sin multiplicación EC
char* bip38_encrypt(const char* privkey_hex, const char* passphrase);

#endif // BIP38_H