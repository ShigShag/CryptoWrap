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
	This function uses aes 256 cbc to crypt and decrypt the given buffer
*/
void crypt_bytes()
{
	uint8_t *ciphertext = NULL;
	uint64_t ciphertext_len;

	uint8_t *plaintext = NULL;
	uint64_t plaintext_len;

	uint32_t key_len = 0;
	uint8_t *random_key = NULL;

	// It is also possible to generate a random key instead of hardcoding it
	if ((random_key = cw_sym_cipher_generate_symmetric_key(CW_AES_256_CBC, (int *)&key_len)) == NULL)
	{
		cw_error_get_last_error_fp_ex(stdout);
		goto END;
	}

	// Encrypt rawData with aes 256 cbc --- ciphertext is allocated within the function
	if (cw_sym_cipher_raw_encrypt_bytes(rawData, sizeof(rawData),
										&ciphertext, &ciphertext_len,
										random_key, key_len,
										iv, sizeof(iv),
										CW_AES_256_CBC, 0) != 1)
	{
		cw_error_get_last_error_fp_ex(stdout);
		goto END;
	}

	printf("Generated ciphertext AES 256 CBC:\n");
	BIO_dump_fp(stdout, ciphertext, ciphertext_len);

	// Decrypt the ciphertext and safe the result into plaintext
	if (cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len,
										&plaintext, &plaintext_len,
										random_key, key_len,
										iv, sizeof(iv),
										CW_AES_256_CBC, 0) != 1)
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
	if (random_key != NULL)
		free(random_key);
}

/*
	This function uses chacha20 to crypt and decrypt the given buffer.
	Plaintext and ciphertext are allocated outside the function by the user
*/
void crypt_bytes_no_alloc()
{
	uint8_t *ciphertext = NULL;
	uint64_t ciphertext_len;

	uint8_t *plaintext = NULL;
	uint64_t plaintext_len;

	// Get the ciphertext len based on encryption algorithm and plaintxt length
	ciphertext_len = cw_sym_cipher_get_cipher_size(CW_CHACHA_20, sizeof(rawData));

	if ((ciphertext = (uint8_t *)malloc(ciphertext_len)) == NULL)
	{
		fprintf(stderr, "Malloc failed\n");
		goto END;
	}

	// Allocate plaintext with ciphetext len since it is a stream cipher and of the same length
	if ((plaintext = (uint8_t *)malloc(ciphertext_len)) == NULL)
	{
		fprintf(stderr, "Malloc failed\n");
		goto END;
	}

	// Encrypt rawData with chacha 20 --- ciphertext is NOT allocated within the function
	if (cw_sym_cipher_raw_encrypt_bytes(rawData, sizeof(rawData),
										&ciphertext, &ciphertext_len,
										key, sizeof(key),
										iv, sizeof(iv),
										CW_CHACHA_20, SYMMETRIC_CIPHER_NO_ALLOC) != 1)
	{
		cw_error_get_last_error_fp_ex(stdout);
		goto END;
	}

	printf("\nGenerated ciphertext CHACHA20:\n");
	BIO_dump_fp(stdout, ciphertext, ciphertext_len);

	// Decrypt the ciphertext and safe the result into plaintext
	if (cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len,
										&plaintext, &plaintext_len,
										key, sizeof(key),
										iv, sizeof(iv),
										CW_CHACHA_20, SYMMETRIC_CIPHER_NO_ALLOC) != 1)
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

/*
	This function uses AES 256 CTR to crypt and decrypt the contents of the buffer
	within the buffer itself
*/
void crypt_bytes_in_place()
{
	// Many of the truths that we cling to depend on our viewpoint. - Obi Wan Kenobi
	uint8_t wise_quotes[60] = {
		0x4D, 0x61, 0x6E, 0x79, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20,
		0x74, 0x72, 0x75, 0x74, 0x68, 0x73, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20,
		0x77, 0x65, 0x20, 0x63, 0x6C, 0x69, 0x6E, 0x67, 0x20, 0x74, 0x6F, 0x20,
		0x64, 0x65, 0x70, 0x65, 0x6E, 0x64, 0x20, 0x6F, 0x6E, 0x20, 0x6F, 0x75,
		0x72, 0x20, 0x76, 0x69, 0x65, 0x77, 0x70, 0x6F, 0x69, 0x6E, 0x74, 0x2E};

	uint8_t *wise_quotes_ptr = wise_quotes;

	// Crypts the contents of wise_quotes in place. SYMMETRIC_CIPHER_CRYPT_IN_PLACE or SYMMETRIC_CIPHER_NO_ALLOC flag need to bet set.
	// Be careful when using block cipher modes, since padding increases the ciphertext size
	// Ciphertext size can be NULL but one can also pass in a value
	if (cw_sym_cipher_raw_encrypt_bytes(wise_quotes_ptr, sizeof(wise_quotes),
										&wise_quotes_ptr, NULL,
										key, sizeof(key),
										iv, sizeof(iv),
										CW_AES_256_CTR, SYMMETRIC_CIPHER_CRYPT_IN_PLACE) != 1)
	{
		cw_error_get_last_error_fp_ex(stdout);
		goto END;
	}

	printf("\nGenerated ciphertext AES 256 CTR:\n");
	BIO_dump_fp(stdout, wise_quotes, sizeof(wise_quotes));

	// Decrypt the ciphertext and safe the result into plaintext
	if (cw_sym_cipher_raw_decrypt_bytes(wise_quotes_ptr, sizeof(wise_quotes),
										&wise_quotes_ptr, NULL,
										key, sizeof(key),
										iv, sizeof(iv),
										CW_AES_256_CTR, SYMMETRIC_CIPHER_CRYPT_IN_PLACE) != 1)
	{
		cw_error_get_last_error_fp_ex(stdout);
		goto END;
	}

	printf("\nGenerated plaintext:\n");
	BIO_dump_fp(stdout, wise_quotes, sizeof(wise_quotes));

END:
	return;
}

int main()
{
	crypt_bytes();

	crypt_bytes_no_alloc();

	crypt_bytes_in_place();

	return EXIT_SUCCESS;
}