/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/key_exchange.h"
#include "internal/key_exchange_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <string.h>

#include <openssl/core_names.h>
#include <openssl/obj_mac.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/param_build.h>

int cw_keyexch_dhec_init(PEER_DATA *local_peer, cw_elliptic_curve_type curve_id)
{
    if (local_peer == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    PEER_DATA local_peer_interal = NULL;

    // Allocate space for new peer_data struct
    if ((local_peer_interal = (PEER_DATA)OPENSSL_zalloc(sizeof(struct peer_data))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    if (cw_ecc_generate_key_pair((ECC_KEY_PAIR *)&local_peer_interal->privk, curve_id) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        return 0;
    }

    // Get size of public key
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &local_peer_interal->pubk_len) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    // Allocate size for public key
    if ((local_peer_interal->pubk_data = OPENSSL_zalloc(local_peer_interal->pubk_len)) == NULL)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // filter out public key in byte form
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, local_peer_interal->pubk_data,
                                        local_peer_interal->pubk_len, NULL) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    *local_peer = local_peer_interal;

    return 1;
}

int cw_keyexch_dhec_init_from_ec(PEER_DATA *local_peer, ECC_KEY_PAIR key_pair)
{
    if (local_peer == NULL || key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    PEER_DATA local_peer_interal = NULL;

    // Allocate space for new peer_data struct
    if ((local_peer_interal = (PEER_DATA)OPENSSL_zalloc(sizeof(struct peer_data))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    local_peer_interal->privk = key_pair;

    // Get size of public key
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &local_peer_interal->pubk_len) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    // Allocate size for public key
    if ((local_peer_interal->pubk_data = OPENSSL_zalloc(local_peer_interal->pubk_len)) == NULL)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // filter out public key in byte form
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, local_peer_interal->pubk_data,
                                        local_peer_interal->pubk_len, NULL) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    *local_peer = local_peer_interal;

    return 1;
}

int cw_keyexch_dhec_to_ec(PEER_DATA local_peer, ECC_KEY_PAIR key_pair)
{
    if (local_peer == NULL || key_pair == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (local_peer->privk == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    key_pair = local_peer->privk;

    return 1;
}

int cw_keyexch_dhec_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                           uint8_t **secret, uint64_t *secret_len, const uint8_t flags)
{
    if (local_peer == NULL || remote_peer_pubk == NULL || remote_peer_pubk_len == 0 || secret == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_PKEY *remote_peer_pkey = NULL;

    int ret_value = 1;

    if ((remote_peer_pkey = CW_keyexch_derive_public_key_internal(local_peer, remote_peer_pubk, remote_peer_pubk_len, CW_KEYEXCH_ECDH)) == NULL)
        return 0;

    if (CW_keyexch_derive_internal(local_peer, remote_peer_pkey, secret, secret_len, flags) != 1)
        ret_value = 0;

    EVP_PKEY_free(remote_peer_pkey);

    return ret_value;
}

int cw_keyexch_x25519_init(PEER_DATA *local_peer, uint8_t *custom_key, const uint32_t custom_key_len)
{
    if (local_peer == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    PEER_DATA local_peer_interal = NULL;

    // Allocate space for new peer_data struct
    if ((local_peer_interal = (PEER_DATA)OPENSSL_zalloc(sizeof(struct peer_data))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // Create a new random key
    if (custom_key == NULL)
    {
        if ((local_peer_interal->privk = EVP_PKEY_Q_keygen(NULL, NULL, SN_X25519)) == NULL)
        {
            CW_keyexch_peer_cleanup_internal(local_peer_interal);
            CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X25519);
            return 0;
        }
    }
    else
    {
        if ((local_peer_interal->privk = EVP_PKEY_new_raw_private_key_ex(NULL, SN_X25519, NULL, custom_key, custom_key_len)) == NULL)
        {
            CW_keyexch_peer_cleanup_internal(local_peer_interal);
            CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X25519);
            return 0;
        }
    }

    // Get size of public key
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &local_peer_interal->pubk_len) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    // Allocate size for public key
    if ((local_peer_interal->pubk_data = OPENSSL_zalloc(local_peer_interal->pubk_len)) == NULL)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // filter out public key in byte form
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, local_peer_interal->pubk_data,
                                        local_peer_interal->pubk_len, NULL) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    *local_peer = local_peer_interal;

    return 1;
}

int cw_keyexch_x25519_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                             uint8_t **secret, uint64_t *secret_len, const uint8_t flags)
{
    if (local_peer == NULL || remote_peer_pubk == NULL || remote_peer_pubk_len == 0 || secret == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_PKEY *remote_peer_pkey = NULL;

    int ret_value = 1;

    if ((remote_peer_pkey = CW_keyexch_derive_public_key_internal(local_peer, remote_peer_pubk, remote_peer_pubk_len, CW_KEYEXCH_X25519)) == NULL)
        return 0;

    if (CW_keyexch_derive_internal(local_peer, remote_peer_pkey, secret, secret_len, flags) != 1)
        ret_value = 0;

    EVP_PKEY_free(remote_peer_pkey);

    return ret_value;
}

int cw_keyexch_x448_init(PEER_DATA *local_peer, uint8_t *custom_key, const uint32_t custom_key_len)
{
    if (local_peer == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    PEER_DATA local_peer_interal = NULL;

    // Allocate space for new peer_data struct
    if ((local_peer_interal = (PEER_DATA)OPENSSL_zalloc(sizeof(struct peer_data))) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // Create a new random key
    if (custom_key == NULL)
    {
        if ((local_peer_interal->privk = EVP_PKEY_Q_keygen(NULL, NULL, SN_X448)) == NULL)
        {
            CW_keyexch_peer_cleanup_internal(local_peer_interal);
            CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_Q_KEYGEN_X448);
            return 0;
        }
    }
    else
    {
        if ((local_peer_interal->privk = EVP_PKEY_new_raw_private_key_ex(NULL, SN_X448, NULL, custom_key, custom_key_len)) == NULL)
        {
            CW_keyexch_peer_cleanup_internal(local_peer_interal);
            CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PRIVATE_KEY_EX_CUSTOM_X448);
            return 0;
        }
    }

    // Get size of public key
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &local_peer_interal->pubk_len) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    // Allocate size for public key
    if ((local_peer_interal->pubk_data = OPENSSL_zalloc(local_peer_interal->pubk_len)) == NULL)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
        return 0;
    }

    // filter out public key in byte form
    if (EVP_PKEY_get_octet_string_param(local_peer_interal->privk, OSSL_PKEY_PARAM_PUB_KEY, local_peer_interal->pubk_data,
                                        local_peer_interal->pubk_len, NULL) != 1)
    {
        CW_keyexch_peer_cleanup_internal(local_peer_interal);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_GET_OCTET_STRING_PARAM);
        return 0;
    }

    *local_peer = local_peer_interal;

    return 1;
}

int cw_keyexch_x448_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                           uint8_t **secret, uint64_t *secret_len, const uint8_t flags)
{
    if (local_peer == NULL || remote_peer_pubk == NULL || remote_peer_pubk_len == 0 || secret == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_PKEY *remote_peer_pkey = NULL;

    int ret_value = 1;

    if ((remote_peer_pkey = CW_keyexch_derive_public_key_internal(local_peer, remote_peer_pubk, remote_peer_pubk_len, CW_KEYEXCH_X448)) == NULL)
        return 0;

    if (CW_keyexch_derive_internal(local_peer, remote_peer_pkey, secret, secret_len, flags) != 1)
        ret_value = 0;

    EVP_PKEY_free(remote_peer_pkey);

    return ret_value;
}

int cw_keyexch_peer_get_pub_key(PEER_DATA local_peer, uint8_t **pub_key, uint32_t *pub_key_len, const uint8_t flags)
{
    if (local_peer == NULL || pub_key == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    if (!(flags & KEYEXCH_NO_ALLOC))
    {
        if ((*pub_key = OPENSSL_zalloc(local_peer->pubk_len)) == NULL)
        {
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    memcpy(*pub_key, local_peer->pubk_data, local_peer->pubk_len);

    if (pub_key_len != NULL)
        *pub_key_len = local_peer->pubk_len;

    return 1;
}

void cw_keyexch_peer_data_delete(PEER_DATA local_peer)
{
    if (local_peer == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return;
    }

    CW_keyexch_peer_cleanup_internal(local_peer);
}