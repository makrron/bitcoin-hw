// hex_to_bytes.h

#ifndef HEX_TO_BYTES_H
#define HEX_TO_BYTES_H

#include <stddef.h> // para size_t

// Declara la función hex_to_bytes para que pueda ser utilizada por otros archivos
int hex_to_bytes(const char *hex, unsigned char *bytes, size_t bytes_len);
char* bytes_to_hex(const unsigned char* bytes, size_t len);

#endif // HEX_TO_BYTES_H
