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

void hmac()
{
    uint8_t *hmac = NULL;
    uint64_t hmac_len = 0;

    // Create an hmac with SHA 3 384
    if (cw_hmac_raw_ex(message, sizeof(message), key, sizeof(key), CW_HMAC_SHA3_384, &hmac, &hmac_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the result
    printf("Generated HMAC\n");
    BIO_dump_fp(stdout, hmac, hmac_len);

    // Verify the hmac
    if (cw_hmac_verify(message, sizeof(message), hmac, hmac_len, key, sizeof(key), CW_HMAC_SHA3_384) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nHmac verification successful\n\n");

END:
    if (hmac != NULL)
        free(hmac);
}

void cmac()
{
    uint8_t *cmac = NULL;
    uint64_t cmac_len = 0;

    // Create an cmac with AES 256
    if (cw_cmac_raw_ex(message, sizeof(message), key, sizeof(key), CW_CMAC_AES_256_CBC, &cmac, &cmac_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the result
    printf("Generated CMAC\n");
    BIO_dump_fp(stdout, cmac, cmac_len);

    // Verify the cmac
    if (cw_cmac_verify(message, sizeof(message), cmac, cmac_len, key, sizeof(key), CW_CMAC_AES_256_CBC) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nCMAC verification successful\n\n");

END:
    if (cmac != NULL)
        free(cmac);
}

void gmac()
{
    uint8_t *gmac = NULL;
    uint64_t gmac_len = 0;

    // Create an gmac with AES GCM 192
    if (cw_gmac_raw_ex(message, sizeof(message), key, sizeof(key), iv, sizeof(iv), CW_GMAC_AES_GCM_256, &gmac, &gmac_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the result
    printf("Generated GMAC\n");
    BIO_dump_fp(stdout, gmac, gmac_len);

    // Verify the gmac
    if (cw_gmac_verify(message, sizeof(message), gmac, gmac_len, key, sizeof(key), iv, sizeof(iv), CW_GMAC_AES_GCM_256) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGMAC verification successful\n\n");

END:
    if (gmac != NULL)
        free(gmac);
}

void siphash()
{
    uint8_t *siphash = NULL;
    uint32_t siphash_len = 0;

    // Create an siphash -> Siphash key must be exactly 16 bytes long
    // If MAC_SET_OUT_LEN is used set siphash_len to either 8 or 16
    if (cw_siphash_raw_ex(message, sizeof(message), key, 16, SIPHASH_COMPRESSION_ROUNDS, SIPHASH_FINALIZATION_ROUNDS,
                          &siphash, &siphash_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the result
    printf("Generated SIPHASH\n");
    BIO_dump_fp(stdout, siphash, siphash_len);

    // Verify the siphash
    if (cw_siphash_verify(message, sizeof(message), siphash, siphash_len, key, 16,
                          SIPHASH_COMPRESSION_ROUNDS, SIPHASH_FINALIZATION_ROUNDS) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nSIPHASH verification successful\n\n");

END:
    if (siphash != NULL)
        free(siphash);
}

void kmac()
{
    uint8_t *kmac = NULL;
    uint32_t kmac_len = 345;

    // This can be anything
    uint8_t custom_value[] = {0x00, 0x11, 0x22};

    // Create an kmac 256 mac
    if (cw_kmac_raw_ex(message, sizeof(message), key, sizeof(key), CW_KMAC_256, custom_value, sizeof(custom_value),
                       &kmac, &kmac_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the result
    printf("Generated KMAC\n");
    BIO_dump_fp(stdout, kmac, kmac_len);

    // Verify the kmac
    if (cw_kmac_verify(message, sizeof(message), kmac, kmac_len, key, sizeof(key),
                       custom_value, sizeof(custom_value), CW_KMAC_256) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nKMAC verification successful\n\n");

END:
    if (kmac != NULL)
        free(kmac);
}

int main()
{
    hmac();

    cmac();

    gmac();

    siphash();

    kmac();

    return EXIT_SUCCESS;
}