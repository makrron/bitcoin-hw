#include <stdio.h>
#include <stdlib.h>
#include "privateKey.h"
#include "publicKey.h"
#include "pk2hash.h"
#include "hex_bytes.h"
#include "signature.h"
#include "generateAddress.h"
#include "bip38.h"

// Función para leer la clave privada desde un archivo
char* read_private_key_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error abriendo el archivo.\n");
        return NULL;
    }

    char* key = malloc(65); //la clave privada es un hexadecimal de 64 caracteres + '\0'
    if (fscanf(file, "%64s", key) != 1) {
        printf("Error leyendo la clave privada del archivo.\n");
        free(key);
        fclose(file);
        return NULL;
    }

    fclose(file);
    return key;
}

int main() {
    const char* private_key_hex = generate_private_key();
    //lee de un fichero la clave privada
    //const char* private_key_hex = read_private_key_from_file("private_key.txt");

    if (private_key_hex != NULL) {
        printf("Hex Private Key: %s\n", private_key_hex);

        // Separación de operaciones con la clave privada
        printf("\n--- Operaciones con la Clave Privada ---\n");

        // Cifrando la clave privada con bip38
        const char* passphrase = "TestingOneTwoThree";
        char* encrypted_privkey = bip38_encrypt(private_key_hex, passphrase);

        if (encrypted_privkey != NULL) {
            printf("Clave privada cifrada (BIP38): %s\n", encrypted_privkey);
            free(encrypted_privkey);
        } else {
            printf("Fallo al cifrar la clave privada.\n");
        }

        // Convertir a WIF
        char* wif = convert_private_key_to_wif(private_key_hex);
        printf("[TESTNET] WIF Private Key: %s\n", wif);

        // Separación de operaciones con la clave pública
        printf("\n--- Operaciones con la Clave Pública ---\n");

        // Generar la clave pública
        unsigned char public_key[33]; // Tamaño para clave pública comprimida
        size_t public_key_len = sizeof(public_key);

        if (generate_public_key_from_hex(private_key_hex, public_key, &public_key_len)) {
            // Convertir la clave pública a hexadecimal para su uso con hash160
            char* public_key_hex = bytes_to_hex(public_key, public_key_len);
            printf("[COMPRESSED] Hex Public Key:  %s\n", public_key_hex);

            // Generar el hash160 de la clave pública
            char* hash160 = malloc(40); // 20 bytes en hexadecimal
            publicKeytoHash(public_key_hex, hash160);
            printf("Public Key Hash: %s\n", hash160);

            // Separación de la firma
            printf("\n--- Firma de Transacción ---\n");

            // Crear una transacción de prueba
            unsigned char tx_hash[32] = {
                    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D,
                    0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D, 0xBA, 0xAD, 0xF0, 0x0D
            };
            printf("Tx Hash: ");
            for (size_t i = 0; i < 32; i++) {
                printf("%02x", tx_hash[i]);
            }
            printf("\n");

            // Firmar la transacción
            unsigned char signature[72];
            size_t signature_len = sizeof(signature);
            if (sign_transaction(private_key_hex, tx_hash, signature, &signature_len)) {
                printf("Firma generada con éxito.\n");
                printf("Firma DER: ");
                for (size_t i = 0; i < signature_len; i++) {
                    printf("%02x", signature[i]);
                }
                printf("\n");

                // Verificar la firma
                int result = verify_signature(public_key_hex, tx_hash, signature, signature_len);
                if (result) {
                    printf("Firma verificada con éxito.\n");
                } else {
                    printf("Error al verificar la firma.\n");
                }
            } else {
                printf("Error al firmar la transacción.\n");
            }

            // Separación de la generación de la dirección
            printf("\n--- Generación de Dirección P2PKH ---\n");

            // Generar la dirección P2PKH
            char* testnet_address = P2PKH_address(hash160, 1); // 1 para testnet
            char* mainnet_address = P2PKH_address(hash160, 0); // 0 para mainnet
            if (testnet_address) {
                printf("Dirección P2PKH [TESTNET]: %s\n", testnet_address);
                printf("Dirección P2PKH [MAINNET]: %s\n", mainnet_address);
                free((char*)testnet_address); // Asegúrate de liberar la memoria
                free((char*)mainnet_address); // Asegúrate de liberar la memoria
            } else {
                printf("Error al generar la dirección P2PKH.\n");
            }

            free(public_key_hex); // No olvides liberar la memoria
            free(hash160); // No olvides liberar la memoria
        } else {
            printf("Error al generar la clave pública.\n");
        }

        free((char*)private_key_hex); // Asegúrate de liberar la clave privada generada
    } else {
        printf("Error al generar la clave privada.\n");
    }

    return 0;
}