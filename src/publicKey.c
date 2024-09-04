// publicKey.c

#include "publicKey.h"
#include <stdio.h>
#include <secp256k1.h>
#include "hex_bytes.h" // Asegúrate de tener este archivo en tu proyecto

// Implementa la función declarada en publicKey.h
int generate_public_key_from_hex(const char *private_key_hex, unsigned char *public_key, size_t *public_key_len) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char private_key[32];

    if (!hex_to_bytes(private_key_hex, private_key, sizeof(private_key))) {
        fprintf(stderr, "Error al convertir la clave privada hex a bytes\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        fprintf(stderr, "Error al generar la clave pública\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    if (!secp256k1_ec_pubkey_serialize(ctx, public_key, public_key_len, &pubkey, SECP256K1_EC_COMPRESSED)) {
        fprintf(stderr, "Error al serializar la clave pública\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_context_destroy(ctx);
    return 1; // Éxito
}

// genera clave publica sin compresion a partir de la clave privada
int generate_uncompress_public_key_from_hex(const char *private_key_hex, unsigned char *public_key, size_t *public_key_len) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    unsigned char private_key[32];

    if (!hex_to_bytes(private_key_hex, private_key, sizeof(private_key))) {
        fprintf(stderr, "Error al convertir la clave privada hex a bytes\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, private_key)) {
        fprintf(stderr, "Error al generar la clave pública\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    if (!secp256k1_ec_pubkey_serialize(ctx, public_key, public_key_len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
        fprintf(stderr, "Error al serializar la clave pública\n");
        secp256k1_context_destroy(ctx);
        return 0;
    }

    secp256k1_context_destroy(ctx);
    return 1; // Éxito
}