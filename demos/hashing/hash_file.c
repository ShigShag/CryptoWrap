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

/*
This function creates a hash Sha_224 hash for a given file 
In this example the executable file itself is being hashed
*/
void hash_file_raw(const char *path)
{
    uint8_t *hash = NULL;
    uint32_t hash_len;

    // Hash bytes --- hash gets allocated within the function
    if (cw_hash_file(path, CW_SHA_224, &hash, &hash_len, 0) != 1)
    {
        // If the function fails print the error message
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Generated executable Hash: \n");

    // Openssl output
    BIO_dump_fp(stdout, hash, hash_len);

END:
    if (hash != NULL)
        free(hash);
}



int main(int argc, char *argv[])
{
    if(argc > 0)
        hash_file_raw(argv[0]);

    return EXIT_SUCCESS;
}