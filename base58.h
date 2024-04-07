//
// Created by makrron on 7/04/24.
//

#ifndef PRUEBASC_BASE58_H
#define PRUEBASC_BASE58_H

// Función para codificar una cadena hexadecimal a Base58.
void encode_base58(const char* hex, char* output);
void decode_base58(const char* base58, char* output);


#endif //PRUEBASC_BASE58_H
