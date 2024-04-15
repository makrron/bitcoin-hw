//
// Created by makrron on 15/04/24.
//
// signature.c

#include "signature.h"
#include "hex_bytes.h"

// Implementa la función de firma

int sign_transaction(const char *priv_key_hex, const unsigned char *hash, unsigned char *signature, size_t *signature_len) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_signature sig;

    unsigned char priv_key[32];
    hex_to_bytes(priv_key_hex, priv_key, 32);  // Convierte la clave privada de hex a bytes

    if (!secp256k1_ecdsa_sign(ctx, &sig, hash, priv_key, NULL, NULL)) {
        secp256k1_context_destroy(ctx);
        return 0; // Falla al firmar
    }

    // Serializar la firma en formato DER
    if (!secp256k1_ecdsa_signature_serialize_der(ctx, signature, signature_len, &sig)) {
        secp256k1_context_destroy(ctx);
        return 0; // Falla al serializar
    }
    secp256k1_context_destroy(ctx);
    return 1; // Éxito
}
int verify_signature(const char *pub_key_hex, const unsigned char *hash, const unsigned char *signature, size_t signature_len) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    unsigned char pub_key[33];
    hex_to_bytes(pub_key_hex, pub_key, 33);  // Convierte la clave pública de hex a bytes

    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, pub_key, 33)) {
        secp256k1_context_destroy(ctx);
        return 0; // Error al parsear la clave pública
    }

    if (!secp256k1_ecdsa_signature_parse_der(ctx, &sig, signature, signature_len)) {
        secp256k1_context_destroy(ctx);
        return 0; // Error al parsear la firma
    }

    // Normalizar la firma para asegurarse de que está en la forma "low S"
    secp256k1_ecdsa_signature_normalize(ctx, NULL, &sig);

    // Verificar la firma
    int is_valid = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubkey);

    secp256k1_context_destroy(ctx);
    return is_valid;
}
