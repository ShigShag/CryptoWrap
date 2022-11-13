/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#ifndef MAC_INTERNAL_H
#define MAC_INTERNAL_H

#include <openssl/evp.h>
#include <internal/helper.h>

#define SIPHASH_REQUIRED_KEY_SIZE 16

#define MAC_CLEANUP(ctx, mac_impl, params)   \
    CW_HELPER_CLEAR_PARAMS_INTERNAL(params); \
    cw_mac_cleanup_internal(ctx, mac_impl)

#define MAC_FILE_CLEANUP(ctx, mac_impl, params, fp) \
    do                                              \
    {                                               \
        CW_HELPER_CLEAR_PARAMS_INTERNAL(params);    \
        cw_mac_cleanup_internal(ctx, mac_impl);     \
        if (fp != NULL)                             \
        {                                           \
            fclose(fp);                             \
        }                                           \
    } while (0)

void cw_mac_cleanup_internal(EVP_MAC_CTX *ctx, EVP_MAC *mac);

int cw_mac_process_internal(EVP_MAC_CTX *ctx,
                            const uint8_t *in, const uint64_t in_len,
                            uint8_t **out, uint64_t *out_len,
                            const uint8_t flags);

int cw_mac_process_file_internal(EVP_MAC_CTX *ctx, FILE *reader,
                                 uint8_t **out, uint64_t *out_len,
                                 const uint8_t flags);

EVP_MAC_CTX *cw_mac_stream_init_ctx_internal(const char *algorithm,
                                             const uint8_t *key, const uint32_t key_len,
                                             OSSL_PARAM *params);

#endif