// hex_to_bytes.c

#include "hex_bytes.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// Función auxiliar para convertir un solo carácter hexadecimal a su valor numérico equivalente
static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1; // Indicador de error
}

// Implementación de la función hex_to_bytes
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        // La longitud de la cadena hexadecimal debe ser par
        return 0;
    }

    size_t expected_bytes_len = hex_len / 2;
    if (bytes_len < expected_bytes_len) {
        // El array de bytes proporcionado no es lo suficientemente grande
        return 0;
    }

    for (size_t i = 0, j = 0; i < hex_len; i += 2, j++) {
        int high = hex_char_to_int(hex[i]);
        int low = hex_char_to_int(hex[i + 1]);
        if (high == -1 || low == -1) {
            // Carácter no válido encontrado
            return 0;
        }
        bytes[j] = (unsigned char)((high << 4) | low);
    }

    return 1; // Éxito
}

// Función para convertir bytes a una cadena hexadecimal
char* bytes_to_hex(const unsigned char* bytes, size_t len) {
    char* hex_str = (char*)malloc(len * 2 + 1); // Cada byte se convierte en 2 caracteres hexadecimales
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_str + i * 2, "%02x", bytes[i]);
    }
    hex_str[len * 2] = '\0'; // Asegurarse de terminar la cadena
    return hex_str;
}