#ifndef PRUEBASC_PRIVATEKEY_H
#define PRUEBASC_PRIVATEKEY_H

#include <stdlib.h>

char* to_hexadecimal(unsigned char* hash, size_t size);
char* generate_private_key();
void convert_private_key_to_wif(const char* hex_priv_key, char* wif_output, size_t len);
unsigned char* add_checksum_to_extended_key(unsigned char* extended_key_bytes, size_t len);

#endif //PRUEBASC_PRIVATEKEY_H