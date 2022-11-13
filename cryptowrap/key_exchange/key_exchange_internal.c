/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "internal/key_exchange_internal.h"
#include "internal/fetching.h"
#include "internal/error/error_internal.h"

#include <openssl/core_names.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/param_build.h>

void CW_keyexch_peer_cleanup_internal(PEER_DATA local_peer_interal)
{
    if (local_peer_interal != NULL)
    {
        if (local_peer_interal->privk != NULL)
            EVP_PKEY_free(local_peer_interal->privk);

        if (local_peer_interal->pubk_data != NULL)
            OPENSSL_clear_free(local_peer_interal->pubk_data, local_peer_interal->pubk_len);

        OPENSSL_clear_free(local_peer_interal, sizeof(struct peer_data));
    }
}

EVP_PKEY *CW_KEYEXCH_X25519_get_public_key_internal(uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len)
{
    EVP_PKEY *ret = NULL;

    if ((ret = EVP_PKEY_new_raw_public_key_ex(NULL, SN_X25519, NULL, remote_peer_pubk, remote_peer_pubk_len)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X25519);
        return NULL;
    }

    return ret;
}

EVP_PKEY *CW_KEYEXCH_X448_get_public_key_internal(uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len)
{
    EVP_PKEY *ret = NULL;

    if ((ret = EVP_PKEY_new_raw_public_key_ex(NULL, SN_X448, NULL, remote_peer_pubk, remote_peer_pubk_len)) == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_NEW_RAW_PUBLIC_KEY_EX_X448);
        return NULL;
    }

    return ret;
}

EVP_PKEY *CW_KEYEXCH_ECDH_get_public_key_internal(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len)
{
    EVP_PKEY *ret_value = NULL;
    char local_curve[30] = {0};
    uint64_t local_curve_len = 0;

    int failed = 1;

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;

    EVP_PKEY_CTX *ctx = NULL;

    // Get curve type
    EVP_PKEY_get_utf8_string_param(local_peer->privk, "group", local_curve, sizeof(local_curve), &local_curve_len);

    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, local_curve, local_curve_len) != 1)
        goto END;

    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, remote_peer_pubk, remote_peer_pubk_len) != 1)
        goto END;

    if ((params = OSSL_PARAM_BLD_to_param(bld)) == NULL)
        goto END;

    if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
        goto END;

    if (EVP_PKEY_fromdata_init(ctx) != 1)
        goto END;

    if (EVP_PKEY_fromdata(ctx, &ret_value, EVP_PKEY_PUBLIC_KEY, params) != 1)
        goto END;

    failed = 0;
END:
    OSSL_PARAM_BLD_free(bld);

    if (params != NULL)
        OSSL_PARAM_free(params);

    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    if (failed)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_ECDH_GET_PEER_PUBLIC_KEY);
    }

    // In case EVP_PKEY_fromdata fails and still sets ret_value to a value != NULL
    return (failed == 1) ? NULL : ret_value;
}

EVP_PKEY *CW_keyexch_derive_public_key_internal(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len, CW_KEYEXCH_MODE_INTERNAL mode)
{
    if (remote_peer_pubk == NULL || remote_peer_pubk_len == 0)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    switch (mode)
    {
    case CW_KEYEXCH_X25519:
        return CW_KEYEXCH_X25519_get_public_key_internal(remote_peer_pubk, remote_peer_pubk_len);

    case CW_KEYEXCH_X448:
        return CW_KEYEXCH_X448_get_public_key_internal(remote_peer_pubk, remote_peer_pubk_len);

    case CW_KEYEXCH_ECDH:
        return CW_KEYEXCH_ECDH_get_public_key_internal(local_peer, remote_peer_pubk, remote_peer_pubk_len);

    default:
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_DERIVE_PUBLIC_KEY_WRONG_MODE);
        return NULL;
    }
}

int CW_keyexch_derive_internal(PEER_DATA local_peer, EVP_PKEY *remote_peer_pkey, uint8_t **secret, uint64_t *secret_len, const uint8_t flags)
{
    if (local_peer == NULL || remote_peer_pkey == NULL || secret == NULL)
    {
        CW_ERROR_RAISE(CW_ERROR_ID_PARAM_MISSING);
        return 0;
    }

    EVP_PKEY_CTX *ctx = NULL;
    uint64_t secret_len_intern = 0;

    // Create pkey context
    if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, local_peer->privk, NULL)) == NULL)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_CTX_NEW_FROM_PKEY);
        return 0;
    }

    // Init key derive context
    if (EVP_PKEY_derive_init(ctx) == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_INIT);
        return 0;
    }

    // Add the remote peer public key
    if (EVP_PKEY_derive_set_peer(ctx, remote_peer_pkey) == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE_SET_PEER);
        return 0;
    }

    // Get length of the secret
    if (EVP_PKEY_derive(ctx, NULL, &secret_len_intern) == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE);
        return 0;
    }

    if (!(flags & KEYEXCH_NO_ALLOC))
    {
        // Allocate space for the secret
        if ((*secret = OPENSSL_zalloc(secret_len_intern * sizeof(uint8_t))) == NULL)
        {
            EVP_PKEY_CTX_free(ctx);
            CW_ERROR_RAISE(CW_ERROR_ID_ALLOC_OPENSSL_ZALLOC);
            return 0;
        }
    }

    // Derive the secret
    if (EVP_PKEY_derive(ctx, *secret, &secret_len_intern) == 0)
    {
        EVP_PKEY_CTX_free(ctx);
        CW_ERROR_RAISE(CW_ERROR_ID_KEY_EXCH_EVP_PKEY_DERIVE);
        return 0;
    }

    if (secret_len != NULL)
        *secret_len = secret_len_intern;

    EVP_PKEY_CTX_free(ctx);

    return 1;
}
