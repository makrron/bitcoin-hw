#include "privateKey.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include "base58.h"

char* to_hexadecimal(unsigned char* hash, size_t size) {
    char* output = (char*)malloc((size * 2) + 1);
    for (size_t i = 0; i < size; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[size * 2] = '\0';
    return output;
}

char* generate_private_key() {
    FILE *urandom = fopen("/dev/urandom", "r");
    if (urandom == NULL) {
        perror("No se pudo abrir /dev/urandom");
        return NULL;
    }

    unsigned char bytes[32];
    size_t read = fread(bytes, 1, 32, urandom);
    if (read < 32) {
        perror("No se pudo leer suficiente entropía");
        fclose(urandom);
        return NULL;
    }
    fclose(urandom);

    // Convertir los bytes a hexadecimal
    char *private_key = to_hexadecimal(bytes, 32); // Utiliza la función existente to_hexadecimal
    return private_key;
}

char* convert_private_key_to_wif(const char* hex_priv_key) {
    // 1. Clave privada en hexadecimal
    // 2. Añadir '80' al principio y '01' al final
    char extended_key[69]; // 2 (para '80') + 64 (clave privada) + 2 (para '01') + 1 (para '\0')
    sprintf(extended_key, "ef%s01", hex_priv_key);

    // Convertir la clave extendida en formato hexadecimal a bytes
    size_t len = (strlen(extended_key) / 2);
    unsigned char* extended_key_bytes = malloc(len);
    for (size_t i = 0; i < len; i++) {
        sscanf(extended_key + 2 * i, "%2hhx", &extended_key_bytes[i]);
    }

    // 3 y 4. Realizar doble SHA-256 sobre la clave extendida
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(extended_key_bytes, len, hash); // Len ya refleja '80' al principio y '01' al final
    SHA256(hash, SHA256_DIGEST_LENGTH, hash);

    // 5. Tomar los primeros 4 bytes del segundo SHA-256 hash como checksum
    unsigned char checksum[4];
    memcpy(checksum, hash, 4);

    // 6. Añadir los 4 bytes de checksum al final de la clave extendida en bytes
    unsigned char* final_key = malloc(len + 4); // Ajustar para el checksum
    memcpy(final_key, extended_key_bytes, len);
    memcpy(final_key + len, checksum, 4); // Añadir el checksum al final

    char* wif_private_key = malloc(512); // Asegúrate de que sea suficientemente grande.

    // 7. Convertir a Base58
    encode_base58(to_hexadecimal(final_key, len + 4), wif_private_key);

    return wif_private_key;

}