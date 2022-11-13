/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/mac.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// Try not. Do or do not. There is no try
uint8_t message[38] = {
    0x54, 0x72, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x44, 0x6F, 0x20,
    0x6F, 0x72, 0x20, 0x64, 0x6F, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x54,
    0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x20, 0x74,
    0x72, 0x79};

/* A key should never be hardcoded */
uint8_t key[32] = {
    0xE9, 0xC3, 0x2F, 0x3C, 0x62, 0x17, 0x37, 0x3F, 0xE3, 0x4A, 0xA4, 0x26,
    0xCF, 0x85, 0x9D, 0xEF, 0xAB, 0xA2, 0x55, 0x45, 0x57, 0x02, 0x83, 0x8C,
    0xF2, 0x21, 0xBB, 0x2E, 0xEA, 0x20, 0x4E, 0xDF};

/* An initialization vector should never be hardcoded */
uint8_t iv[16] = {
    0x23, 0x9B, 0x9F, 0x7F, 0xE3, 0x9C, 0xC1, 0xA7, 0x6B, 0x55, 0x56, 0x87,
    0x8D, 0x97, 0x06, 0x66};

void mac_stream()
{
    MAC_STREAM_HANDLE handle = NULL;

    uint8_t *mac = NULL;
    uint32_t mac_len = 0;

    // Init the stream -> call the init function for the desired mac function

    if (cw_hmac_stream_init(&handle, key, sizeof(key), CW_HMAC_SHA3_256) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // if (cw_cmac_stream_init(&handle, key, sizeof(key), CW_CMAC_AES_256_CBC) != 1)
    // {
    //     cw_error_get_last_error_fp_ex(stdout);
    //     goto END;
    // }

    // if (cw_gmac_stream_init(&handle, key, sizeof(key), iv, sizeof(iv), CW_GMAC_AES_GCM_256) != 1)
    // {
    //     cw_error_get_last_error_fp_ex(stdout);
    //     goto END;
    // }

    // if (cw_siphash_stream_init(&handle, key, 16, SIPHASH_COMPRESSION_ROUNDS, SIPHASH_FINALIZATION_ROUNDS) != 1)
    // {
    //     cw_error_get_last_error_fp_ex(stdout);
    //     goto END;
    // }

    // if (cw_kmac_stream_init(&handle, key, sizeof(key), NULL, 0, CW_KMAC_256) != 1)
    // {
    //     cw_error_get_last_error_fp_ex(stdout);
    //     goto END;
    // }

    // From now on the process is the same for every mac

    // Update the stream -> In real applications more than one call should be made
    // to this function
    if (cw_mac_stream_update(handle, message, sizeof(message)) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Finalize and receive the mac -> MAC_SET_OUT_LEN can be used here to set the length with mac_len
    if (cw_mac_stream_final(handle, &mac, &mac_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the mac
    printf("Generated mac:\n");
    BIO_dump_fp(stdout, mac, mac_len);

END:
    // Free the handle
    if (handle != NULL)
        cw_mac_stream_delete(handle);

    if (mac != NULL)
        free(mac);
}

int main()
{
    mac_stream();

    return EXIT_SUCCESS;
}