/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/base64.h>
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
    0x6D, 0x65, 0x2E};

void encode_bytes_raw()
{
    uint8_t *encoded = NULL;
    uint64_t encoded_len = 0;

    uint8_t *decoded = NULL;
    uint64_t decoded_len = 0;

    // Encode the data -> output is allocated within the function
    if (cw_base64_raw_encode(rawData, sizeof(rawData), &encoded, &encoded_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print out the encoded buffer
    printf("Base64 encoded buffer:\n");
    BIO_dump_fp(stdout, encoded, encoded_len);

    // Decode the buffer -> plaintext is allocated within the function
    if (cw_base64_raw_decode(encoded, encoded_len, &decoded, &decoded_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print out the encoded buffer
    printf("\nBase64 decoded buffer:\n");
    BIO_dump_fp(stdout, decoded, decoded_len);

END:
    if (encoded != NULL)
        free(encoded);
    if (decoded != NULL)
        free(decoded);
}

int main()
{
    encode_bytes_raw();

    return EXIT_SUCCESS;
}