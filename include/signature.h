// signature.h

#ifndef SIGNATURE_H
#define SIGNATURE_H

#include <stdlib.h>

#include "secp256k1.h"


int sign_transaction(const char *priv_key, const unsigned char *hash, unsigned char *signature, size_t *signature_len);
int verify_signature(const char *pub_key, const unsigned char *hash, const unsigned char *signature, size_t signature_len);

#endif // SIGNATURE_H
