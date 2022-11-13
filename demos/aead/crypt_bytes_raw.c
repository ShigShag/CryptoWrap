/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/aead.h>
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
    0xE9, 0xC3, 0x2F, 0x3C, 0x62, 0x17, 0x32, 0x3F, 0xE3, 0x4A, 0xA4, 0x26,
    0xCF, 0x85, 0x9D, 0xEF, 0xAB, 0xA2, 0x55, 0x45, 0x57, 0x02, 0x83, 0x8C,
    0xF2, 0x21, 0xBB, 0x2E, 0xEA, 0x20, 0x4E, 0xDF};

/* An initialization vector should never be hardcoded */
uint8_t iv[16] = {
    0x23, 0x9B, 0x9F, 0x7F, 0xE3, 0x9C, 0xC1, 0xA7, 0x6B, 0x55, 0x56, 0x87,
    0x8D, 0x97, 0x06, 0x66};

// Additional data can be of any size
uint8_t aad_data[16] = {
    0x0E, 0xB8, 0xF8, 0x2C, 0xE8, 0xA2, 0x7C, 0xD8, 0x36, 0x82, 0x0D, 0x3A,
    0x68, 0x25, 0x4A, 0x1C};

void crypt_bytes()
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    uint8_t *tag = NULL;

    // Length of the tag to be received
    uint32_t tag_len = 16;

    // Get iv length
    int iv_len = cw_aead_get_iv_length(CW_AES_256_GCM);

    // Encrypt rawData with AES GCM 256 --- ciphertext is allocated within the function
    // Any aead_mode may be used here -> make sure to adjust key and iv size
    if (cw_aead_raw_encrypt_bytes(rawData, sizeof(rawData), &ciphertext, &ciphertext_len, key, sizeof(key), iv, iv_len,
                                  aad_data, sizeof(aad_data), &tag, tag_len, CW_AES_256_GCM, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Generated ciphertext AES GCM 256:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    printf("\nGenerated Tag:\n");
    BIO_dump_fp(stdout, tag, tag_len);

    // Decrypt the ciphertext -> Tag needs to be the one obtained when encrypting
    if (cw_aead_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, sizeof(key), iv, iv_len,
                                  aad_data, sizeof(aad_data), tag, tag_len, CW_AES_256_GCM, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGenerated plaintext:\n");
    BIO_dump_fp(stdout, plaintext, plaintext_len);

END:
    if (ciphertext != NULL)
        free(ciphertext);
    if (plaintext != NULL)
        free(plaintext);
}

void crypt_bytes_no_alloc()
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    uint8_t *tag = NULL;

    // Length of the tag to be received
    uint32_t tag_len = 16;

    // Get iv length
    int iv_len = cw_aead_get_iv_length(CW_AES_256_CCM);

    // Obtain expected ciphertext length
    ciphertext_len = cw_aead_get_encrypt_size(sizeof(rawData));

    // Allocate ciphertext
    if ((ciphertext = calloc(ciphertext_len, sizeof(uint8_t))) == NULL)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Allocate tag
    if ((tag = calloc(tag_len, sizeof(uint8_t))) == NULL)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Encrypt rawData with AES OCB 256 --- ciphertext is NOT allocated within the function
    // Any aead_mode may be used here -> make sure to adjust key and iv size
    // AEAD_OUT_NO_ALLOC | AEAD_TAG_NO_ALLOC == AEAD_NO_ALLOC
    if (cw_aead_raw_encrypt_bytes(rawData, sizeof(rawData), &ciphertext, &ciphertext_len, key, sizeof(key), iv, iv_len,
                                  aad_data, sizeof(aad_data), &tag, tag_len, CW_AES_256_CCM, AEAD_OUT_NO_ALLOC | AEAD_TAG_NO_ALLOC) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Generated ciphertext AES GCM 256:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    printf("\nGenerated Tag:\n");
    BIO_dump_fp(stdout, tag, tag_len);

    // Decrypt the ciphertext -> Tag needs to be the one obtained when encrypting
    // Ciphertext will be allocated within the function
    if (cw_aead_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, sizeof(key), iv, iv_len,
                                  aad_data, sizeof(aad_data), tag, tag_len, CW_AES_256_CCM, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nGenerated plaintext:\n");
    BIO_dump_fp(stdout, plaintext, plaintext_len);

END:
    if (ciphertext != NULL)
        free(ciphertext);
    if (plaintext != NULL)
        free(plaintext);
}

int main()
{
    crypt_bytes();

    crypt_bytes_no_alloc();

    return EXIT_SUCCESS;
}