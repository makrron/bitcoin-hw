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
    // 1. Clave privada en hexadecimal
    char* hex_priv_key = "0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
    //printf("1. Take a private key:\n\t%s\n", hex_priv_key);

    // 2. Añadir '80' al principio y '01' al final
    char extended_key[69]; // 2 (para '80') + 64 (clave privada) + 2 (para '01') + 1 (para '\0')
    sprintf(extended_key, "ef%s01", hex_priv_key);
    //printf("2. Add '80' at the beginning and '01' at the end:\n\t%s\n", extended_key);

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
    //printf("3. Perform SHA-256 hash twice on the extended key:\n\t");
    //for (size_t i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    //    printf("%02x", hash[i]);
    //}
    //printf("\n");

    // 5. Tomar los primeros 4 bytes del segundo SHA-256 hash como checksum
    unsigned char checksum[4];
    memcpy(checksum, hash, 4);
    //printf("Checksum: ");
    //for (size_t i = 0; i < 4; i++) {
    //    printf("%02x", checksum[i]);
    //}
    //printf("\n");

    // 6. Añadir los 4 bytes de checksum al final de la clave extendida en bytes
    unsigned char* final_key = malloc(len + 4); // Ajustar para el checksum
    memcpy(final_key, extended_key_bytes, len);
    memcpy(final_key + len, checksum, 4); // Añadir el checksum al final

    char* wif_private_key = malloc(512); // Asegúrate de que sea suficientemente grande.
    encode_base58(to_hexadecimal(final_key, len + 4), wif_private_key);
    //printf("7. Convert the extended key from step 6 into Base58 format:\n\t%s\n", wif_private_key);
    free(final_key);

    return wif_private_key;

}