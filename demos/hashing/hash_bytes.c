/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/hash.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

 uint8_t rawData[195] = {
	0x50, 0x65, 0x61, 0x63, 0x65, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6C,
	0x69, 0x65, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73,
	0x20, 0x6F, 0x6E, 0x6C, 0x79, 0x20, 0x50, 0x61, 0x73, 0x73, 0x69, 0x6F,
	0x6E, 0x2E, 0x20, 0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x50,
	0x61, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x2C, 0x49, 0x20, 0x67, 0x61, 0x69,
	0x6E, 0x20, 0x53, 0x74, 0x72, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x2E, 0x20,
	0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x53, 0x74, 0x72, 0x65,
	0x6E, 0x67, 0x74, 0x68, 0x2C, 0x49, 0x20, 0x67, 0x61, 0x69, 0x6E, 0x20,
	0x50, 0x6F, 0x77, 0x65, 0x72, 0x2E, 0x20, 0x54, 0x68, 0x72, 0x6F, 0x75,
	0x67, 0x68, 0x20, 0x50, 0x6F, 0x77, 0x65, 0x72, 0x2C, 0x49, 0x20, 0x67,
	0x61, 0x69, 0x6E, 0x20, 0x56, 0x69, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x2E,
	0x20, 0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x56, 0x69, 0x63,
	0x74, 0x6F, 0x72, 0x79, 0x20, 0x6D, 0x79, 0x20, 0x63, 0x68, 0x61, 0x69,
	0x6E, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x42, 0x72, 0x6F, 0x6B, 0x65,
	0x6E, 0x2E, 0x20, 0x54, 0x68, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x63, 0x65,
	0x20, 0x73, 0x68, 0x61, 0x6C, 0x6C, 0x20, 0x66, 0x72, 0x65, 0x65, 0x20,
	0x6D, 0x65, 0x2E
};

/*
This function creates a sha256 hash from the given Bytes Sequence
It uses the raw interface so only one call is needed to create the hash
The hash gets allocated within the function and needs to be freed

It also verifies the hash to the byte sequence
*/
void hash_bytes_raw()
{
    uint8_t *hash = NULL;
    uint32_t hash_len;

    // Hash bytes --- hash gets allocated within the function
    if (cw_hash_raw_bytes(rawData, sizeof(rawData), CW_SHA_256, &hash, &hash_len, 0) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Generated Hash: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

    // Verify bytes
    if (cw_hash_verify_bytes(hash, hash_len, rawData, sizeof(rawData), CW_SHA_256) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Hash verification successful\n");

END:
    if (hash != NULL)
        free(hash);
}

/*
This function does the same as hash_bytes_raw() above but sets the HASH_NO_ALLOC flag
This way the hash is not allocated within the function and needs to be allocated by the user
*/
void hash_bytes_raw_no_alloc()
{
    uint8_t *hash = NULL;
    uint32_t hash_len;

    // Retrieve the hash size of sha256
    hash_len = cw_hash_get_len(CW_SHA_256);

    if ((hash = calloc(hash_len, sizeof(uint8_t))) == NULL)
    {
        goto END;
    }

    // Hash bytes --- hash is not within the function
    if (cw_hash_raw_bytes(rawData, sizeof(rawData), CW_SHA_256, &hash, &hash_len, HASH_NO_ALLOC) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGenerated Hash with no allocation flag set: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

    // Verify bytes
    if (cw_hash_verify_bytes(hash, hash_len, rawData, sizeof(rawData), CW_SHA_256) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Hash verification successful\n");

END:
    if (hash != NULL)
        free(hash);
}

/*
This function creates a sha3-512 hash from the given string
It uses the raw interface so only one call is needed to create the hash
The hash gets allocated within the function and needs to be freed

It also verifies the hash to the string
*/
void hash_string_raw()
{
    uint8_t *hash = NULL;
    uint32_t hash_len;

    const char *string_to_hash = "Qui-Gon Jinn said: Your focus determines your reality.";

    // Hash string --- hash gets allocated within the function
    if (cw_hash_raw_string(string_to_hash, CW_SHA_512, &hash, &hash_len, 0) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGenerated Hash: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

    // Verify bytes
    if (cw_hash_verify_string(hash, hash_len, string_to_hash, CW_SHA_512) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Hash verification successful\n");

END:
    if (hash != NULL)
        free(hash);
}

/*
This function creates a sha3-512 hash from the given string
It the tires to verify the hash against a different sequence
The verification fails and an error is displayed
*/
void hash_string_raw_verification_failure()
{
    uint8_t *hash = NULL;
    uint32_t hash_len;

    const char *string_to_hash = "Obi-Wan Kenobi said: In my experience there is no such thing as luck.";
    const char *imposter_string = "I have got a bad feeling about this";

    // Hash string --- hash gets allocated within the function
    if (cw_hash_raw_string(string_to_hash, CW_SHA_512, &hash, &hash_len, 0) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGenerated Hash for failure: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

    // Verify bytes
    if (cw_hash_verify_string(hash, hash_len, imposter_string, CW_SHA_512) != 1)
    {
        // If the function fails print the error message
        printf("\nFailure message:\n");
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Hash verification successful\n");

END:
    if (hash != NULL)
        free(hash);
}

int main()
{
    hash_bytes_raw();

    hash_bytes_raw_no_alloc();

    hash_string_raw();

    hash_string_raw_verification_failure();

    return EXIT_SUCCESS;
}