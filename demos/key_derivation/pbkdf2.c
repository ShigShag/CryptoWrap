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

/*
This function generates a key with pbkdf2
*/
void hkdf_key_gen()
{
    const char *password = "ThisPasswordIsNotSecure";

    uint32_t iterations = PBKDF2_DEFAULT_ITERATIONS;

    uint8_t *key = NULL;
    uint64_t key_len;

    // Create a key with pbkdf2
    if (cw_pbkdf2_ex((uint8_t *)password, strlen(password), salt, sizeof(salt), iterations, CW_KDH_SHA3_512, &key, &key_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }
 
    printf("Key:\n");
    BIO_dump_fp(stdout, key, key_len);

END:
    if (key != NULL)
        free(key);
}

/*
This function generates a key with pbkdf2 and sets a custom output size
Be aware that it cannot be higher than the supplied hash
*/
void pbkdf2_key_gen_custom_output_size()
{
    const char *password = "ThisPasswordIsNotSecure";

    uint32_t iterations = PBKDF2_DEFAULT_ITERATIONS;

    uint8_t *key = NULL;

    // Set output size in variable -> This will get us 10 byte of key material
    uint64_t key_len = 10;

    // Create a key with pbkdf2 and set the flag KEY_DERIVATION_SET_OUTPUT_LEN
    if (cw_pbkdf2_ex((uint8_t *)password, strlen(password), salt, sizeof(salt), iterations, CW_KDH_SHA3_512, &key, &key_len, KEY_DERIVATION_SET_OUTPUT_LEN) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }
 
    printf("\nKey with custom output size:\n");
    BIO_dump_fp(stdout, key, key_len);

END:
    if (key != NULL)
        free(key);
}

int main()
{
    hkdf_key_gen();

    pbkdf2_key_gen_custom_output_size();

    return EXIT_SUCCESS;
}