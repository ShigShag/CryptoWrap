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
#include <openssl/opensslv.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

unsigned char rawData[] = {
    0x50, 0x65, 0x61, 0x63, 0x65, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x6C, 0x69, 0x65, 0x2E,                                           // Peace is a lie
    0x54, 0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6F, 0x6E, 0x6C, 0x79, 0x20, 0x50, 0x61, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x2E, // There is only Pasion.
    0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x50, 0x61, 0x73, 0x73, 0x69, 0x6F, 0x6E, 0x2C,                                     // Through Passion
    0x49, 0x20, 0x67, 0x61, 0x69, 0x6E, 0x20, 0x53, 0x74, 0x72, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x2E,                                     // I gain Strength.
    0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x53, 0x74, 0x72, 0x65, 0x6E, 0x67, 0x74, 0x68, 0x2C,                               // Through Strength,
    0x49, 0x20, 0x67, 0x61, 0x69, 0x6E, 0x20, 0x50, 0x6F, 0x77, 0x65, 0x72, 0x2E,                                                       // I gain Power.
    0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x50, 0x6F, 0x77, 0x65, 0x72, 0x2C,                                                 // Through Power,
    0x49, 0x20, 0x67, 0x61, 0x69, 0x6E, 0x20, 0x56, 0x69, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x2E,                                           // I gain Victory.
    0x54, 0x68, 0x72, 0x6F, 0x75, 0x67, 0x68, 0x20, 0x56, 0x69, 0x63, 0x74, 0x6F, 0x72, 0x79,                                           // Through Victory
    0x6D, 0x79, 0x20, 0x63, 0x68, 0x61, 0x69, 0x6E, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x42, 0x72, 0x6F, 0x6B, 0x65, 0x6E, 0x2E,       // my chains are Broken.
    0x54, 0x68, 0x65, 0x20, 0x46, 0x6F, 0x72, 0x63, 0x65, 0x20, 0x73, 0x68, 0x61, 0x6C, 0x6C, 0x20, 0x66, 0x72, 0x65, 0x65, 0x20        // The Force shall free me.
};

/*
Hash stream is usefull when dealing with data streams wich provide
data in chunks. For the sake of presentation the given byte sequence will
be used
*/
void hash_stream()
{
    uint8_t *hash = NULL;
    uint32_t hash_len;
    HASH_STREAM_HANDLE handle = NULL;

    // Create a hash stream handle for Sha3-512
    if (cw_hash_stream_create_handle(&handle, CW_SHA3_512) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // In real applications this would be the size of the incoming data
    const uint32_t buffer_size = 3;

    // In real applications this value is not needed. There should be other indicators when to stop inputting data
    uint64_t rawData_size = sizeof(rawData);

    do
    {
        // Input more data each iteration
        if (cw_hash_stream_update(handle, rawData + (sizeof(rawData) - rawData_size), buffer_size) != 1)
        {
            cw_error_get_last_error_fp_ex(stdout);
            goto END;
        }
    } while ((rawData_size -= buffer_size) > buffer_size);

    // Last update
    if (cw_hash_stream_update(handle, rawData + (sizeof(rawData) - rawData_size), rawData_size) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Retrieve the hash
    if (cw_hash_stream_finalize(handle, &hash, &hash_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Generated Hash: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

    // Verify the hash
    if (cw_hash_verify_bytes(hash, hash_len, rawData, sizeof(rawData), CW_SHA3_512) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Hash verification successful\n");

END:
    // Delete the stream handle | This can also be achieved by setting the HASH_STREAM_FINAL_DELETE_HANDLE in cw_hash_stream_finalize
    if (handle != NULL)
        cw_hash_stream_delete_handle(handle);
    if (hash != NULL)
        free(hash);
}

int main()
{
    hash_stream();

    return EXIT_SUCCESS;
}