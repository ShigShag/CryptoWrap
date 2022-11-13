/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef KEY_EXCHANGE_INTERNAL_H
#define KEY_EXCHANGE_INTERNAL_H

#include "cryptowrap/key_exchange.h"

#include <openssl/evp.h>

struct peer_data
{
    EVP_PKEY *privk;
    uint8_t *pubk_data;
    uint64_t pubk_len;
};

typedef enum
{
    CW_KEYEXCH_X25519,
    CW_KEYEXCH_X448,
    CW_KEYEXCH_ECDH,
} CW_KEYEXCH_MODE_INTERNAL;

void CW_keyexch_peer_cleanup_internal(PEER_DATA local_peer_interal);

EVP_PKEY *CW_KEYEXCH_X25519_get_public_key_internal(uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len);

EVP_PKEY *CW_KEYEXCH_X448_get_public_key_internal(uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len);

EVP_PKEY *CW_KEYEXCH_ECDH_get_public_key_internal(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len);

EVP_PKEY *CW_keyexch_derive_public_key_internal(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len, CW_KEYEXCH_MODE_INTERNAL mode);

int CW_keyexch_derive_internal(PEER_DATA local_peer, EVP_PKEY *remote_peer_pkey, uint8_t **secret, uint64_t *secret_len, const uint8_t flags);

#endif