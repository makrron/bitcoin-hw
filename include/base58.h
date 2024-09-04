//
// Created by makrron on 7/04/24.
//

#ifndef PRUEBASC_BASE58_H
#define PRUEBASC_BASE58_H
#include "stddef.h"
// Función para codificar una cadena hexadecimal a Base58.
void encode_base58(const char *hex, char *output);
void decode_base58(const char* base58, char* output);
char* encode_base58_bip(const unsigned char* input, size_t input_len);

#endif //PRUEBASC_BASE58_H
