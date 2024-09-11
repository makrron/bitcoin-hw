#include "generateAddress.h"
#include "base58.h"
#include "hex_bytes.h"
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* P2PKH_address(const char* public_key_hash_hex, int network) {
    unsigned char address[25]; // 1 byte para el prefijo + 20 bytes para el hash de la clave pública + 4 bytes para el checksum
    char* output = malloc(50); // Ajustar según la necesidad del tamaño de la salida de base58
    if (!output) {
        fprintf(stderr, "Fallo en la asignación de memoria\n");
        return NULL;
    }

    // Convertir cadena hexadecimal a binario
    unsigned char public_key_hash[20];
    hex_to_bytes(public_key_hash_hex, public_key_hash, sizeof(public_key_hash));

    // Establecer prefijo según la red: 0x00 para Mainnet, 0x6f para Testnet
    address[0] = (network == 0) ? 0x00 : 0x6f;
    memcpy(address + 1, public_key_hash, 20); // Copiar el hash de la clave pública en el buffer de la dirección después del prefijo

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(address, 21, hash); // Hashear los primeros 21 bytes de la dirección
    SHA256(hash, SHA256_DIGEST_LENGTH, hash); // Hashear el hash para obtener el checksum

    // Copiar los primeros 4 bytes del resultado en los últimos 4 bytes del array de la dirección para el checksum
    memcpy(address + 21, hash, 4);

    // Convertir la dirección (ahora array completo de 25 bytes) a una cadena hexadecimal para la codificación Base58
    char* hex; // Cada byte puede ser de hasta 2 caracteres hexadecimales
    hex = bytes_to_hex(address, 25);

    // Codificación Base58 de la dirección
    encode_base58(hex, output); // Suponiendo que encode_base58 usa una entrada hexadecimal

    free(hex);

    return output;
}