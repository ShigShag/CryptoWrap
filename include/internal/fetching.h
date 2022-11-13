/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef FETCHING_H
#define FETCHING_H

#include "cryptowrap/hash.h"
#include "cryptowrap/symmetric_cipher.h"
#include "cryptowrap/mac.h"
#include "cryptowrap/ecc.h"
#include "cryptowrap/aead.h"
#include "cryptowrap/key_derivation.h"
#include "cryptowrap/rsa.h"

#include <openssl/evp.h>

/* Hash fetching */

// Fetch str identifier
char *cw_fetch_hash_str_internal(hash_algorithm algorithm_id);

// Fetch id identifier
int cw_fetch_hash_nid_internal(hash_algorithm algorithm_id);

// Fetch length of hash
int cw_fetch_hash_len_internal(hash_algorithm algorithm_id);

// Fetch implementation
EVP_MD *cw_fetch_hash_impl_internal(hash_algorithm algorithm_id);

// Free digest
void cw_fetch_free_hash_impl_internal(EVP_MD *digest_impl);

/* Symmetric cipher fetching */

// Fetch str identifier
char *cw_fetch_symmetric_cipher_str_internal(cw_symmetric_cipher_algorithm algorithm_id);

// Fetch id identifier
int cw_fetch_symmetric_cipher_nid_internal(cw_symmetric_cipher_algorithm algorithm_id);

// Fetch implementation
EVP_CIPHER *fetch_symmetric_cipher_impl(cw_symmetric_cipher_algorithm algorithm_id);

// Fetch required key and iv length
int cw_fetch_symmetric_cipher_key_and_iv_length(cw_symmetric_cipher_algorithm algorithm_id, int *key_len, int *iv_len);

// Free digest
void cw_fetch_free_symmetric_cipher_impl_internal(EVP_CIPHER *symmetric_cipher_impl);

/* AEAD fetching */

// Fetch str identifier
char *cw_fetch_aead_str_internal(aead_mode algorithm_id);

// Fetch id identifier
int cw_fetch_aead_nid_internal(aead_mode algorithm_id);

// Fetch implementation
EVP_CIPHER *cw_fetch_aead_impl_internal(aead_mode algorithm_id);

// Fetch required key and iv length
int cw_fetch_aead_key_and_iv_length_internal(aead_mode algorithm_id, int *key_len, int *iv_len);

void cw_fetch_free_aead_impl_internal(EVP_CIPHER *symmetric_cipher_authentication_impl);

/* MAC FETCHING */
char *cw_fetch_hmac_internal_internal(cw_hmac_digest algorithm_id);

char *cw_fetch_gmac_internal(cw_gmac_cipher algorithm_id);

char *cw_fetch_kmac_internal(cw_kmac_mode algorithm_id);

/* Elliptic curves */
int cw_fetch_ec_curve_nid_internal(cw_elliptic_curve_type curve_type);

char *cw_fetch_ec_curve_str_internal(cw_elliptic_curve_type curve_type);

char *cw_fetch_ec_serialization_type_str_internal(cw_ecc_serialization_type output_type);

char *cw_fetch_ec_signature_str_internal(cw_ecc_signature_hash signature_id);

/* RSA */
int cw_fetch_rsa_padding_mode_internal(cw_rsa_padding_mode padding_mode);

char *cw_fetch_rsa_serialization_type_internal(cw_rsa_serialization_type output_mode);

/* Key derivation */
#define FETCH_ARGON2_INVALID (-1)

int cw_fetch_key_derivation_argon2_mode_internal(cw_argon2_mode mode);

#endif