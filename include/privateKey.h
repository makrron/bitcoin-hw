#ifndef PRUEBASC_PRIVATEKEY_H
#define PRUEBASC_PRIVATEKEY_H

#include <stdlib.h>

char* to_hexadecimal(unsigned char* hash, size_t size);
char* generate_private_key();
char* convert_private_key_to_wif(const char* hex_priv_key);


#endif //PRUEBASC_PRIVATEKEY_H