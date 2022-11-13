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

/* An initialization vector should never be hardcoded */
uint8_t iv[16] = {
    0x23, 0x9B, 0x9F, 0x7F, 0xE3, 0x9C, 0xC1, 0xA7, 0x6B, 0x55, 0x56, 0x87,
    0x8D, 0x97, 0x06, 0x66};

/*
    This function uses the high interface crypt and decrypt the given buffer with AES 256 XTS
*/
void crypt_via_high_interface()
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    SYMMETRIC_KEY_OBJECT key_obj = NULL;

    uint8_t *key = NULL;
    int key_len;

    // Generate a random key which suites AES 256 XTS
    if ((key = cw_sym_cipher_generate_symmetric_key(CW_AES_256_XTS, &key_len)) == NULL)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Generate a key object
    if ((key_obj = cw_sym_cipher_high_generate_symmetric_object(&key, key_len, CW_AES_256_XTS, 0)) == NULL)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Encrypt the data
    if (cw_sym_cipher_high_generate_cipher_text(key_obj, rawData, sizeof(rawData), &ciphertext, &ciphertext_len) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ciphertext, ciphertext_len);

    // Decrypt the text
    if (cw_sym_cipher_high_generate_plain_text(key_obj, ciphertext, ciphertext_len, &plaintext, &plaintext_len) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // This has the same effect 
    // if (cw_sym_cipher_high_generate_plain_text_key_only(key, key_len, ciphertext, ciphertext_len, &plaintext, &plaintext_len) != 1)
    // {
    //     cw_error_get_last_error_fp_ex(stdout);
    //     goto END;
    // }

    printf("\nDecrypted text:\n");
    BIO_dump_fp(stdout, plaintext, plaintext_len);

END:
    if (key != NULL)
        free(key);
    if (ciphertext != NULL)
        free(ciphertext);
    if (plaintext != NULL)
        free(plaintext);
}

int main()
{
    crypt_via_high_interface();

    return EXIT_SUCCESS;
}