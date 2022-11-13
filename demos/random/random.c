/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/random.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

void random_number()
{
    uint32_t random_number = 0;
    int64_t random_number_large = 0;

    if (CW_RANDOM_NUMBER(&random_number) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    if (CW_RANDOM_NUMBER(&random_number_large) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    printf("Random uint32_t: %u\nRandom int64_t: %lu\n",
           random_number, random_number_large);
}

void random_bytes()
{
    uint8_t *random_buffer = NULL;
    uint64_t buffer_size = 100;

    if (cw_random_bytes(&random_buffer, buffer_size, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    printf("\nRandom Bytes:\n");
    BIO_dump_fp(stdout, random_buffer, buffer_size);
}

void random_bytes_no_alloc()
{
    uint8_t *random_buffer = NULL;
    uint64_t buffer_size = 100;

    if ((random_buffer = calloc(buffer_size, sizeof(uint8_t))) == NULL)
    {
        fprintf(stderr, "Calloc failed\n");
        return;
    }

    if (cw_random_bytes(&random_buffer, buffer_size, RANDOM_NO_ALLOC) != 1)
    {
        free(random_buffer);
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    printf("\nRandom Bytes no alloc:\n");
    BIO_dump_fp(stdout, random_buffer, buffer_size);
    free(random_buffer);
}

int main()
{
    random_number();

    random_bytes();

    random_bytes_no_alloc();

    return EXIT_SUCCESS;
}