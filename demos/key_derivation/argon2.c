/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/key_derivation.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint8_t salt[64] = {
    0xB6, 0xF2, 0xFD, 0x31, 0x05, 0x31, 0x19, 0xE6, 0xCB, 0x8F, 0x74, 0xD7,
    0x93, 0x4E, 0x68, 0x93, 0x94, 0xAC, 0x95, 0xF3, 0xA1, 0xC4, 0x6E, 0xE6,
    0x08, 0x60, 0xBC, 0xC9, 0x0E, 0xC1, 0xC3, 0xAD, 0xED, 0xB4, 0x5C, 0x19,
    0x96, 0x44, 0x91, 0xD4, 0xF7, 0xEC, 0x89, 0x47, 0x0A, 0xF4, 0x8D, 0xD4,
    0x71, 0xBA, 0x3E, 0x9E, 0x87, 0xAF, 0x48, 0x90, 0x1F, 0xCC, 0x1B, 0x24,
    0x80, 0x6D, 0x39, 0xF7};

void argon2_raw()
{
    const char *password = "123456";

    uint32_t time_cost = ARGON2_TIME_COST;
    uint32_t memory_cost = ARGON2_MEMORY_DFAULT;
    uint32_t parallelism = ARGON2_PARALLELISM_DEFAULT;

    // You can choose between three modes
    cw_argon2_mode mode = CW_ARGON2_ID;
    // cw_argon2_mode mode = CW_ARGON2_I;
    // cw_argon2_mode mode = CW_ARGON2_D;

    uint8_t *raw_hash = NULL;

    // Output size needs to be passed to the function
    // In this case a raw_hash of size 32 is requested
    uint32_t key_len = 32;

    if (cw_argon2_raw(time_cost, memory_cost, parallelism, (const void *)password, strlen(password), salt, sizeof(salt),
                      &raw_hash, key_len, mode, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Key:\n");
    BIO_dump_fp(stdout, raw_hash, key_len);

    if (cw_argon2_raw_verify(raw_hash, key_len, time_cost, memory_cost, parallelism,
                             (const void *)password, strlen(password), salt, sizeof(salt), mode) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nVerification successful\n");

END:
    if (raw_hash != NULL)
        free(raw_hash);
}

void argon2_encoded()
{
    const char *password = "123456";

    uint32_t time_cost = ARGON2_TIME_COST;
    uint32_t memory_cost = ARGON2_MEMORY_DFAULT;
    uint32_t parallelism = ARGON2_PARALLELISM_DEFAULT;

    // You can choose between three modes
    cw_argon2_mode mode = CW_ARGON2_ID;
    // cw_argon2_mode mode = CW_ARGON2_I;
    // cw_argon2_mode mode = CW_ARGON2_D;

    // Variable to save the encoded string
    char *encoded = NULL;
    size_t encoded_len = 0;

    // Output size needs to be passed to the function
    // In this case a raw_hash of size 32 is requested
    uint32_t key_len = 32;

    if (cw_argon2_encoded(time_cost, memory_cost, parallelism, password, strlen(password),
                          salt, sizeof(salt), key_len, &encoded, &encoded_len, mode, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nEncoded Argon2 String:\n%s\n", encoded);

END:
    if (encoded != NULL)
        free(encoded);
}

void argon2_encoded_verify()
{
    const char *password = "123456";

    uint32_t time_cost = ARGON2_TIME_COST;
    uint32_t memory_cost = ARGON2_MEMORY_DFAULT;
    uint32_t parallelism = ARGON2_PARALLELISM_DEFAULT;

    // You can choose between three modes
    cw_argon2_mode mode = CW_ARGON2_ID;
    // cw_argon2_mode mode = CW_ARGON2_I;
    // cw_argon2_mode mode = CW_ARGON2_D;

    // Variable to save the encoded string
    char *encoded = NULL;
    size_t encoded_len = 0;

    // Output size needs to be passed to the function
    // In this case a raw_hash of size 32 is requested
    uint32_t key_len = 32;

    // Create encoded hash
    if (cw_argon2_encoded(time_cost, memory_cost, parallelism, password, strlen(password),
                          salt, sizeof(salt), key_len, &encoded, &encoded_len, mode, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Verify the password against an encoded string
    if (cw_argon2_verify(encoded, password, strlen(password), mode) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nVerification against encoded string successful\n");

END:

    if (encoded != NULL)
        free(encoded);
}

int main()
{
    argon2_raw();

    argon2_encoded();

    argon2_encoded_verify();

    return EXIT_SUCCESS;
}