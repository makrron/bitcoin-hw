#include <stdio.h>
#include <stdlib.h>
#include "privateKey.h"
#include "publicKey.h"
#include "pk2hash.h"
#include "hex_bytes.h"
#include "signature.h"


int main() {
    const char* private_key_hex = generate_private_key();
    if (private_key_hex != NULL) {
        printf("Hex Private Key: %s\n", private_key_hex);

        unsigned char public_key[33]; // Tamaño para clave pública comprimida
        size_t public_key_len = sizeof(public_key);

        //convertir a WIF
        char* wif = convert_private_key_to_wif(private_key_hex);
        printf("[TESNET] WIF Private Key: %s\n", wif);

        if (generate_public_key_from_hex(private_key_hex, public_key, &public_key_len)) {
            // Convertir la clave pública a hexadecimal para su uso con hash160
            char* public_key_hex = bytes_to_hex(public_key, public_key_len);
            printf("[COMPRESSED] Hex Public Key:  %s\n", public_key_hex);

            char* hash160 = (char*)malloc(40); // 20 bytes en hexadecimal
            publicKeytoHash(public_key_hex, hash160);
            printf("Public Key Hash: %s\n", hash160);

            // Creamos una tx en hex de prueba:
            unsigned char tx_hash[32] = {
                    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
                    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D
            };
            //print tx hash
            printf("Tx Hash: ");
            for (size_t i = 0; i < 32; i++) {
                printf("%02x", tx_hash[i]);
            }
            printf("\n");
            // Espacio para almacenar la firma
            unsigned char signature[72];
            size_t signature_len = sizeof(signature);
            // Intenta firmar el hash de la transacción
            if (sign_transaction(private_key_hex, tx_hash, signature, &signature_len)) {
                printf("Firma generada con éxito.\n");
                printf("Firma DER: ");
                for (size_t i = 0; i < signature_len; i++) {
                    printf("%02x", signature[i]);
                }
                printf("\n");

                // si la firma es válida verificamos la firma con la clave pública
                int result = verify_signature(public_key_hex, tx_hash, signature, signature_len);
                if (result) {
                    printf("La firma es válida.\n");
                } else {
                    printf("La firma no es válida.\n");
                }
            } else {
                printf("Error al firmar la transacción.\n");
            }

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
