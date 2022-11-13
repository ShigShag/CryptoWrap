/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef RSA_INTERNAL_H
#define RSA_INTERNAL_H

#include "cryptowrap/rsa.h"

#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

#define RSA_PUBLIC_KEY 0
#define RSA_PRIVATE_KEY 1

#define RSA_IS_DER(serialization_type) (serialization_type == CW_RSA_DER)
#define RSA_IS_PEM(serialization_type) (serialization_type == CW_RSA_PEM)

#define RSA_IS_OAEP(padding_mode) (padding_mode >= CW_RSA_PKCS1_OAEP_SHA1_PADDING && padding_mode <= CW_RSA_PKCS1_OAEP_SHA512_PADDING)
#define RSA_IS_PSS(padding_mode) (padding_mode == CW_RSA_PKCS1_PSS_PADDING)

#define RSA_CRYPT_CLEANUP(ctx, md, out, out_len, flags)            \
    do                                                             \
    {                                                              \
        if (ctx != NULL)                                           \
            EVP_PKEY_CTX_free(ctx);                                \
        if (md != NULL)                                            \
            EVP_MD_free(md);                                       \
        if (!(flags & RSA_NO_ALLOC) && out != NULL && out_len > 0) \
        {                                                          \
            OPENSSL_clear_free(out, out_len);                      \
            out = NULL;                                            \
        }                                                          \
    } while (0)

void cw_rsa_encoder_cleanup_internal(OSSL_ENCODER_CTX *encoder, OSSL_DECODER_CTX *decoder);

int cw_rsa_write_key_internal(FILE *fp, CW_RSA_KEY_PAIR key_pair, const char *passphrase, cw_rsa_serialization_type output_type, int key_type);

int cw_rsa_load_key_internal(FILE *fp, const char *passphrase, const char output_type, CW_RSA_KEY_PAIR *key_pair, int key_type);

char *cw_rsa_map_sign_digest_internal(cw_rsa_signature_hash hash);

int cw_rsa_sign_bytes_internal(CW_RSA_KEY_PAIR key_pair, const void *in, const uint32_t in_len, cw_rsa_signature_hash hash, int padding_mode,
                               uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

int cw_rsa_verify_signature_internal(CW_RSA_KEY_PAIR key_pair, const void *in, const uint32_t in_len,
                                     const uint8_t *signature, const uint64_t signature_len, cw_rsa_signature_hash hash, int padding_mode);

void cw_rsa_crypt_bytes_cleanup_internal(EVP_PKEY_CTX *ctx, EVP_MD *md);

#endif