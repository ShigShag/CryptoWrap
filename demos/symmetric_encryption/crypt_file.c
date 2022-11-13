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

#define FILE_PATH "test_file"
#define FILE_PATH_TWO "test_file_two"

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

int fill_file()
{
    const char *file_path = FILE_PATH;

    FILE *fp;

    if ((fp = fopen(file_path, "wb")) == NULL)
    {
        fprintf(stderr, "Could not open file: %s\n", file_path);
        return 0;
    }

    fwrite(rawData, sizeof(uint8_t), sizeof(rawData), fp);

    fclose(fp);

    return 1;
}

int compare_file_to_test_vector()
{
    const char *file_path = FILE_PATH;

    // Compare file contents to the buffer
    uint8_t buffer[sizeof(rawData)] = {0};

    int success = 0;
    long file_size;
    FILE *fp;

    if ((fp = fopen(file_path, "rb")) == NULL)
    {
        fprintf(stderr, "Could not open file: %s\n", file_path);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    rewind(fp);

    if (file_size != sizeof(rawData))
    {
        fprintf(stderr, "File size is different to test_vector size");
        goto END;
    }

    fread(buffer, sizeof(uint8_t), sizeof(buffer), fp);

    if (CRYPTO_memcmp(buffer, rawData, sizeof(buffer)) != 0)
    {
        fprintf(stderr, "File cotent is different to test_vector content");
        goto END;
    }

    success = 1;
END:
    fclose(fp);

    return success;
}

/*
This function crypts a file in place
*/
void encrypt_file_in_place()
{
    const char *file_path = FILE_PATH;

    // Encrypt the file
    if (cw_sym_cipher_file_encrypt(file_path, NULL, key, sizeof(key), NULL, 0, CW_AES_256_ECB) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    // Decrypt the file
    if (cw_sym_cipher_file_decrypt(file_path, NULL, key, sizeof(key), NULL, 0, CW_AES_256_ECB) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    if (compare_file_to_test_vector() != 1)
    {
        printf("Test inplace crypt failed\n");
        return;
    }

    printf("Test inplace crypt successful\n");
}

/*
This function crypts a file contents and puts it
into a different file
*/
void encrypt_file_out_file()
{
    const char *file_path = FILE_PATH;
    const char *file_path2 = FILE_PATH_TWO;

    // Encrypt the file and put the ciphertext into a different file
    if (cw_sym_cipher_file_encrypt(file_path, file_path2, key, sizeof(key), NULL, 0, CW_AES_256_ECB) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    // Decrypt the file and put the plaintext into the original file
    if (cw_sym_cipher_file_decrypt(file_path2, file_path, key, sizeof(key), NULL, 0, CW_AES_256_ECB) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return;
    }

    if (compare_file_to_test_vector() != 1)
    {
        printf("Test  output file failed\n");
        return;
    }

    printf("Test output file successful\n");
}

int main()
{
    if (fill_file() != 1)
        return EXIT_FAILURE;

    encrypt_file_in_place();

    if (fill_file() != 1)
        return EXIT_FAILURE;

    encrypt_file_out_file();
}