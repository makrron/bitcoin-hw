#include "base58.h"
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void encode_base58(const char* hex, char* output) {
    BIGNUM *num = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_hex2bn(&num, hex);

    // Preparar estructuras para la división y el residuo.
    BIGNUM *divisor = BN_new();
    BIGNUM *remainder = BN_new();
    BN_set_word(divisor, 58);

    // Calcular el tamaño máximo del resultado en base58.
    int output_size = strlen(hex) * 2; // Asumiendo que esto es suficiente.
    char* temp_output = calloc(output_size, sizeof(char));
    if (temp_output == NULL) return;

    int index = output_size - 1; // Iniciar desde el final.
    temp_output[index] = '\0'; // Asegurar que la cadena esté terminada.

    // Convertir de base10 a base58.
    while (BN_cmp(num, BN_value_one()) >= 0) {
        BN_div(num, remainder, num, divisor, ctx);
        int rem = BN_get_word(remainder);
        temp_output[--index] = BASE58_CHARS[rem];
    }

    // Añadir '1' para cada cero inicial en hexadecimal.
    for (size_t i = 0; hex[i] == '0' && hex[i + 1] == '0'; i += 2) {
        temp_output[--index] = '1';
    }

    // Copiar el resultado al output.
    strcpy(output, &temp_output[index]);

    // Liberar recursos.
    //BN_free(num);
    BN_free(divisor);
    BN_free(remainder);
    BN_CTX_free(ctx);
    free(temp_output);
}

void decode_base58(const char* base58, char* output) {
    BIGNUM *num = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    BN_zero(num);

    BIGNUM *base = BN_new();
    BN_set_word(base, 58); // Base para decodificación.

    BIGNUM *multiplier = BN_new();
    BN_one(multiplier); // Comenzamos con el multiplicador en 1.

    // Convertir de base58 a base10.
    int len = strlen(base58);
    for (int i = len - 1; i >= 0; i--) {
        char *char_ptr = strchr(BASE58_CHARS, base58[i]);
        if (char_ptr) {
            int index = char_ptr - BASE58_CHARS;
            BIGNUM *add = BN_new();
            BN_set_word(add, index);
            BN_mul(add, add, multiplier, ctx); // add = index * multiplier.
            BN_add(num, num, add); // num += add.
            BN_free(add);
        } else {
            fprintf(stderr, "Invalid Base58 character: %c\n", base58[i]);
            BN_free(num);
            BN_CTX_free(ctx);
            return;
        }
        BN_mul(multiplier, multiplier, base, ctx); // Actualizar el multiplicador.
    }

    // Convertir el número BIGNUM a cadena hexadecimal.
    char *hex = BN_bn2hex(num);
    // Eliminar los ceros iniciales si son necesarios.
    size_t hex_len = strlen(hex);
    int leading_zeros = 0;
    for (int i = 0; i < len && base58[i] == '1'; i++) {
        leading_zeros += 2; // Cada '1' en Base58 indica dos ceros iniciales en hexadecimal.
    }
    int total_len = leading_zeros + hex_len + 1; // +1 para el carácter nulo.
    if (total_len % 2 != 0) {
        // Asegurar que la longitud total sea par agregando un cero adicional si es necesario.
        leading_zeros++;
    }
    memset(output, 0, total_len);
    for (int i = 0; i < leading_zeros; i++) {
        output[i] = '0';
    }
    strcat(output, hex);

    // Liberar recursos.
    BN_free(num);
    BN_free(base);
    BN_free(multiplier);
    BN_CTX_free(ctx);
    OPENSSL_free(hex);
}
