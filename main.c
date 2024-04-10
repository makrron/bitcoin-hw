#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "privateKey.h"
#include "publicKey.h"


int main() {

    const char* private_key_hex = generate_private_key();
    if (private_key_hex != NULL) {
        printf("Clave privada en hexadecimal: %s\n", private_key_hex);

        unsigned char public_key[33]; // Tamaño para clave pública comprimida

        char *wif_private_key = NULL;
        wif_private_key = convert_private_key_to_wif(private_key_hex);
        printf("Private Key: %s\n", wif_private_key);



        size_t public_key_len = sizeof(public_key);

        if (generate_public_key_from_hex(private_key_hex, public_key, &public_key_len)) {
            printf("Clave pública: ");
            for (size_t i = 0; i < public_key_len; i++) {
                printf("%02x", public_key[i]);
            }
            printf("\n");
        } else {
            printf("Error al generar la clave pública.\n");
        }


        // Liberar la memoria
        free(wif_private_key);

    } else {
        printf("Error al generar la clave privada.\n");
    }


    return 0;
}

