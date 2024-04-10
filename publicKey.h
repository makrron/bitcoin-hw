// publicKey.h

#ifndef PUBLIC_KEY_H
#define PUBLIC_KEY_H

#include <stdlib.h> // para size_t

int generate_public_key_from_hex(const char *private_key_hex, unsigned char *public_key, size_t *public_key_len);

#endif // PUBLIC_KEY_H
