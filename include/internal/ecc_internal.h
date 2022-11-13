/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef EC_INTERNAL_H
#define EC_INTERNAL_H

#include "cryptowrap/ecc.h"

#include <openssl/evp.h>
#include <stdio.h>

#define ECC_PUBLIC_KEY 0
#define ECC_PRIVATE_KEY 1

#define EC_IS_DER(serialization_type) (serialization_type == CW_ECC_DER)
#define EC_IS_PEM(serialization_type) (serialization_type == CW_ECC_PEM)

void cw_ecc_encoder_cleanup_internal(OSSL_ENCODER_CTX *encoder, OSSL_DECODER_CTX *decoder);

int cw_ecc_write_key_internal(FILE *fp, EVP_PKEY *pkey, const char *passphrase, cw_ecc_serialization_type output_type, int key_type);

int cw_ecc_load_key_internal(FILE *fp, const char *passphrase, cw_ecc_serialization_type output_type, EVP_PKEY **pkey, int key_type);

int cw_ecc_sign_bytes_internal(EVP_PKEY *pkey, const uint8_t *in, const uint64_t in_len, cw_ecc_signature_hash hash,
                              uint8_t **signature, uint64_t *signature_len, const uint8_t flags);

int cw_ecc_verify_signature_internal(EVP_PKEY *pkey, const uint8_t *in, const uint64_t in_len, uint8_t *signature,
                                    const uint64_t signature_len, cw_ecc_signature_hash hash);

#endif