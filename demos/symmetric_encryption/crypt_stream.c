/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/symmetric_cipher.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// Try not. Do or do not. There is no try
uint8_t rawData[38] = {
    0x54, 0x72, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x44, 0x6F, 0x20,
    0x6F, 0x72, 0x20, 0x64, 0x6F, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x54,
    0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x20, 0x74,
    0x72, 0x79};

/* A key should never be hardcoded */
uint8_t key[32] = {
    0xE9, 0xC3, 0x2F, 0x3C, 0x62, 0x17, 0x37, 0x3F, 0xE3, 0x4A, 0xA4, 0x26,
    0xCF, 0x85, 0x9D, 0xEF, 0xAB, 0xA2, 0x55, 0x45, 0x57, 0x02, 0x83, 0x8C,
    0xF2, 0x21, 0xBB, 0x2E, 0xEA, 0x20, 0x4E, 0xDF};

uint8_t iv[16] = {
    0x23, 0x9B, 0x9F, 0x7F, 0xE3, 0x9C, 0xC1, 0xA7, 0x6B, 0x55, 0x56, 0x87,
    0x8D, 0x97, 0x06, 0x66};

#define STREAM_BLOCK_SIZE 1

/*
This method crypts rawData byte by byte. This is no real life application but
shows how the stream interface works
*/
void crypt_stream()
{
    uint8_t *ciphertext = NULL;

    int ciphertext_temp = 0;
    
    uint64_t ciphertext_len = 0;
    uint64_t expected_ciphertext_len;

    CIPHER_STREAM_HANDLE handle = NULL;
    int success = 0;

    // Get and allocate ciphertext space
    expected_ciphertext_len = cw_sym_cipher_get_cipher_size(CW_AES_256_CTR, sizeof(rawData));

    if ((ciphertext = calloc(expected_ciphertext_len, sizeof(uint8_t))) == NULL)
    {
        fprintf(stderr, "Calloc failed\n");
        goto END;
    }

    // Create the stream handle by setting mode, key and iv | In order to decrypt use SYM_CIPHER_STREAM_DECRYPT
    if (cw_sym_cipher_stream_create_handle(&handle, CW_AES_256_CTR, key, sizeof(key), iv, sizeof(iv), SYM_CIPHER_STREAM_ENCRYPT) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Keep updating the stream and write the encrypted data into ciphertext
    for (uint64_t i = 0; i < sizeof(rawData); i++)
    {
        if (cw_sym_cipher_stream_update(handle, ciphertext + ciphertext_len, &ciphertext_temp, rawData + i, STREAM_BLOCK_SIZE) != 1)
        {
            cw_error_get_last_error_fp_ex(stdout);
            goto END;
        }

        ciphertext_len += ciphertext_temp;
    }

    if (cw_sym_cipher_stream_final(handle, ciphertext + ciphertext_len, &ciphertext_temp) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    ciphertext_len += ciphertext_temp;

    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    success = 1;

END:
    // Free the handle
    if (handle != NULL)
        cw_sym_cipher_stream_delete_handle(handle);

    if (ciphertext != NULL)
        free(ciphertext);

    if (success)
        printf("\nEncryption succeeded\n");
    else
        printf("\nEncryption failed\n");
}

int main()
{
    crypt_stream();

    return EXIT_SUCCESS;
}