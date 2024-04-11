#include <stdio.h>
#include <stdlib.h>
#include "privateKey.h"
#include "publicKey.h"
#include "pk2hash.h"
#include "hex_bytes.h"


int main() {
    const char* private_key_hex = generate_private_key();
    if (private_key_hex != NULL) {
        printf("Hex Private Key: %s\n", private_key_hex);

        unsigned char public_key[33]; // Tamaño para clave pública comprimida
        size_t public_key_len = sizeof(public_key);

        if (generate_public_key_from_hex(private_key_hex, public_key, &public_key_len)) {
            // Convertir la clave pública a hexadecimal para su uso con hash160
            char* public_key_hex = bytes_to_hex(public_key, public_key_len);
            printf("[COMPRESSED] Hex Public Key:  %s\n", public_key_hex);

            char* hash160 = (char*)malloc(40); // 20 bytes en hexadecimal
            publicKeytoHash(public_key_hex, hash160);
            printf("Hash160: %s\n", hash160);

            free(public_key_hex); // No olvides liberar la memoria
            free(hash160); // No olvides liberar la memoria
        } else {
            printf("Error al generar la clave pública.\n");
        }

        // Liberar la memoria y otros recursos como antes
        free((char*)private_key_hex); // Asegúrate de liberar la clave privada generada

    } else {
        printf("Error al generar la clave privada.\n");
    }

    return 0;
}
