/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file symmetric_cipher.h
 * @author Shig Shag
 * @brief Symmetric cryptography
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef SYMMETRIC_CIPHER_H
#define SYMMETRIC_CIPHER_H

#include <stdio.h>
#include <stdint.h>

/**
 * @brief Symmetric cipher modes available
 * 
 */
typedef enum cw_symmetric_cipher_algorithm
{
    CW_AES_128_ECB,
    CW_AES_128_CBC,
    CW_AES_128_CFB1,
    CW_AES_128_CFB8,
    CW_AES_128_CFB,
    CW_AES_128_CTR,
    CW_AES_128_XTS,
    CW_AES_128_OFB,
    CW_AES_192_ECB,
    CW_AES_192_CBC,
    CW_AES_192_CFB1,
    CW_AES_192_CFB8,
    CW_AES_192_CFB,
    CW_AES_192_CTR,
    CW_AES_192_OFB,
    CW_AES_256_ECB,
    CW_AES_256_CBC,
    CW_AES_256_CFB1,
    CW_AES_256_CFB8,
    CW_AES_256_CFB,
    CW_AES_256_CTR,
    CW_AES_256_XTS,
    CW_AES_256_OFB,

    CW_AES_128_WRAP,
    CW_AES_192_WRAP,
    CW_AES_256_WRAP,

    CW_ARIA_128_ECB,
    CW_ARIA_128_CBC,
    CW_ARIA_128_CFB1,
    CW_ARIA_128_CFB8,
    CW_ARIA_128_CFB,
    CW_ARIA_128_CTR,
    CW_ARIA_128_OFB,
    CW_ARIA_192_ECB,
    CW_ARIA_192_CBC,
    CW_ARIA_192_CFB1,
    CW_ARIA_192_CFB8,
    CW_ARIA_192_CFB,
    CW_ARIA_192_CTR,
    CW_ARIA_192_OFB,
    CW_ARIA_256_ECB,
    CW_ARIA_256_CBC,
    CW_ARIA_256_CFB1,
    CW_ARIA_256_CFB8,
    CW_ARIA_256_CFB,
    CW_ARIA_256_CTR,
    CW_ARIA_256_OFB,

    CW_CAMELLIA_128_ECB,
    CW_CAMELLIA_128_CBC,
    CW_CAMELLIA_128_CFB1,
    CW_CAMELLIA_128_CFB8,
    CW_CAMELLIA_128_CFB,
    CW_CAMELLIA_128_CTR,
    CW_CAMELLIA_128_OFB,
    CW_CAMELLIA_192_ECB,
    CW_CAMELLIA_192_CBC,
    CW_CAMELLIA_192_CFB1,
    CW_CAMELLIA_192_CFB8,
    CW_CAMELLIA_192_CFB,
    CW_CAMELLIA_192_CTR,
    CW_CAMELLIA_192_OFB,
    CW_CAMELLIA_256_ECB,
    CW_CAMELLIA_256_CBC,
    CW_CAMELLIA_256_CFB1,
    CW_CAMELLIA_256_CFB8,
    CW_CAMELLIA_256_CFB,
    CW_CAMELLIA_256_CTR,
    CW_CAMELLIA_256_OFB,

    CW_CHACHA_20

} cw_symmetric_cipher_algorithm;

/**
 * @brief Output is not allocated within the function
 * 
 */
#define SYMMETRIC_CIPHER_NO_ALLOC 0x00000001
#define SYMMETRIC_CIPHER_CRYPT_IN_PLACE (SYMMETRIC_CIPHER_NO_ALLOC)

/**
 * @brief Encrypt data with symmetric encryption
 * @details This function encrypts data with symmetric encryption. 
 * For in place encryption pass the same Variable to plaintext and ciphertext
 * and set the Flag SYMMETRIC_CIPHER_NO_ALLOC.
 * 
 * @param[in] plaintext Plaintext to be encrypted
 * @param[in] plaintext_len Plaintext length
 * @param[out] ciphertext  Where to write the encrypted plaintext.
 * @param[out] ciphertext_len optional: Where to write the length of the ciphertext
 * @param[in] key Key for encryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] algorithm_id Symmetric cipher algorithm
 * @param[in] flags 
 *      - SYMMETRIC_CIPHER_NO_ALLOC Do not allocate ciphertext
 * @return int Returns 1 for success and 0 for failure
 */
int cw_sym_cipher_raw_encrypt_bytes(const uint8_t *plaintext, const uint64_t plaintext_len,
                                    uint8_t **ciphertext, uint64_t *ciphertext_len,
                                    const uint8_t *key, const uint32_t key_len,
                                    const uint8_t *iv, const uint32_t iv_len,
                                    cw_symmetric_cipher_algorithm algorithm_id, const uint8_t flags);

/**
 * @brief Decrypt data with symmetric encryption
 * @details This function decrypts data with symmetric encryption. 
 * For in place decryption pass the same Variable to ciphertext and plaintext
 * and set the Flag SYMMETRIC_CIPHER_NO_ALLOC.
 * 
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertext_len Ciphertext len
 * @param[out] plaintext Where the decrypted ciphertext.
 * @param[out] plaintext_len optional: Where to write the decrypted ciphertext length
 * @param[in] key  Key for decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] algorithm_id Symmetric cipher algorithm
 * @param[in] flags 
 *      - SYMMETRIC_CIPHER_NO_ALLOC Do not allocate plaintext
 * @return int Returns 1 for success and 0 for failure
 */
int cw_sym_cipher_raw_decrypt_bytes(const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                    uint8_t **plaintext, uint64_t *plaintext_len,
                                    const uint8_t *key, const uint32_t key_len,
                                    const uint8_t *iv, const uint32_t iv_len,
                                    cw_symmetric_cipher_algorithm algorithm_id, const uint8_t flags);

/**
 * @brief Encrypt a file with symmetric cipher
 * @details To crypt a file in place set out_file to NULL.
 * 
 * @param[in, out] in_file File which contents should be encrypted
 * @param[out] out_file Where to write the ciphertext
 * @param[in] key Key for encryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] algorithm_id Symmetric cipher algorithm 
 * @return int Returns 1 for success and 0 for failure
 */
int cw_sym_cipher_file_encrypt(const char *in_file, const char *out_file,
                               const uint8_t *key, const uint32_t key_len,
                               const uint8_t *iv, const uint32_t iv_len,
                               cw_symmetric_cipher_algorithm algorithm_id);

/**
 * @brief Decrypt a file with symmetric cipher
 * @details To decrypt a file in place set out_file to NULL.
 * 
 * @param[in, out] in_file File which contents should be decrypted
 * @param[out] out_file Where to write the plaintext
 * @param[in] key Key for decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] algorithm_id Symmetric cipher algorithm 
 * @return int Returns 1 for success and 0 for failure
 */
int cw_sym_cipher_file_decrypt(const char *in_file, const char *out_file,
                               const uint8_t *key, const uint32_t key_len,
                               const uint8_t *iv, const uint32_t iv_len,
                               cw_symmetric_cipher_algorithm algorithm_id);

/**
 * @brief Symmetric cipher object to save a context for high encryption
 * 
 */
typedef uint8_t *SYMMETRIC_KEY_OBJECT;

/**
 * @brief Key is not copied within the symmetric key object
 * Value is passed by reference
 * 
 */
#define SYM_CIPHER_HIGH_NO_KEY_COPY 0x00000002

/**
 * @brief Generates a symmetric key object which can be used to encrypt or decrypt data
 * 
 * @param[in] key_in Key
 * @param[in] in_key_len Key length
 * @param[in] algorithm Symmetric cipher mode
 * @param[in] flags 
 *      - SYMMETRIC_KEY_OBJECT Key is not copied within the symmetric key object
 * Value is passed by reference
 * @return SYMMETRIC_KEY_OBJECT Returns the symmetric key object which can be used for encryption or decryption
 */
SYMMETRIC_KEY_OBJECT cw_sym_cipher_high_generate_symmetric_object(uint8_t **key_in, const int32_t in_key_len, cw_symmetric_cipher_algorithm algorithm, const uint8_t flags);

/**
 * @brief Delete a symmetric key object
 * 
 * @param[in] key_obj Symmetric key object to be deleted
 */
void cw_sym_cipher_high_delete_symmetric_key_object(SYMMETRIC_KEY_OBJECT key_obj);

/* Generate ciphertext by encrypting a given plaintext */
/**
 * @brief Generate ciphertext by encrypting a given plaintext
 * 
 * @param[in] key_obj Symmetric key object
 * @param[in] plaintext Plaintext to be encrypted
 * @param[in] plaintext_len Plaintext length
 * @param[out] cipher Where to save the ciphertext
 * @param[out] cipher_len Optional: Where to save the ciphertext length 
 * @return int Returns 1 for success and 0 for failure 
 * @pre SYMMETRIC_KEY_OBJECT needs to be created prior to this
 */
int cw_sym_cipher_high_generate_cipher_text(SYMMETRIC_KEY_OBJECT key_obj,
                                            const uint8_t *plaintext, const uint64_t plaintext_len,
                                            uint8_t **cipher, uint64_t *cipher_len);

/**
 * @brief Generate plaintext by decrypting a given ciphertext
 * @details Key is set with key_obj
 *  
 * @param[in] key_obj Symmetric key object
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertext_len Ciphertext length
 * @param[out] plaintext Where to save the plaintext
 * @param[out] plaintext_len Optional: Where to save the plaintext length
 * @return int Returns 1 for success and 0 for failure 
 * @pre SYMMETRIC_KEY_OBJECT needs to be created prior to this
 */
int cw_sym_cipher_high_generate_plain_text(SYMMETRIC_KEY_OBJECT key_obj,
                                           const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                           uint8_t **plaintext, uint64_t *plaintext_len);

/* Generate plaintext using only the key */
/**
 * @brief Generate plaintext by decrypting a given ciphertext
 * @details Key is set manually
 * 
 * @param[in] key Key for decryption
 * @param[in] key_len Key length
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertext_len Ciphertext length
 * @param[out] plaintext Where to save the plaintext
 * @param[out] plaintext_len Optional: Where to save the plaintext length
 * @return int Returns 1 for success and 0 for failure 
 * @pre SYMMETRIC_KEY_OBJECT needs to be created prior to this
 */
int cw_sym_cipher_high_generate_plain_text_key_only(const uint8_t *key, const int32_t key_len,
                                                    const uint8_t *ciphertext, const uint64_t ciphertext_len,
                                                    uint8_t **plaintext, uint64_t *plaintext_len);

/* Stream update based encryption */

/**
 * @brief Encrypt mode for symmetric cipher stream
 * 
 */
#define SYM_CIPHER_STREAM_ENCRYPT 1

/**
 * @brief Decrypt mode for symmetric cipher stream
 * 
 */
#define SYM_CIPHER_STREAM_DECRYPT 0

/**
 * @brief Symmetric cipher stream handle which can be used for updating and finalizing a stream
 * 
 */
typedef void *CIPHER_STREAM_HANDLE;

/**
 * @brief Generate a symmetric cipher stream handle
 * @details A stream handle can be used to en- or decrypt data from continuous data streams.
 * Encryption or decryption nay be set with mode.
 * 
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] algorithm_id Symmetric cipher algorithm
 * @param[in] key Key for encryption or decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] mode Encryption or Decryption
 *      - SYM_CIPHER_STREAM_ENCRYPT for encryption
 *      - SYM_CIPHER_STREAM_DECRYPT for decryption
 * @return int Returns 1 for success and 0 for failure
 */
int cw_sym_cipher_stream_create_handle(CIPHER_STREAM_HANDLE *pstream_handle, cw_symmetric_cipher_algorithm algorithm_id,
                                       const uint8_t *key, const int key_len,
                                       const uint8_t *iv, const int iv_len,
                                       int mode);

/**
 * @brief Update a stream handle with data
 * @details This function can be called multiple times to encrypt or decrypt more data. 
 * This function does not allocate the buffer.
 * 
 * @param[in] stream_handle Stream handle
 * @param[out] out Where to store the processed bytes
 * @param[out] bytes_processed optional: Where to store the processed bytes length
 * @param[in] in Data to be encrypted
 * @param[in] in_len Data length
 * @return int Returns 1 for success and 0 for failure
 * @pre stream_handle needs to be created by cw_sym_cipher_stream_create_handle
 */
int cw_sym_cipher_stream_update(CIPHER_STREAM_HANDLE stream_handle, uint8_t *out, int *bytes_encrypted, const uint8_t *in, const int in_len);

/**
 * @brief Finalize a symmetric cipher stream
 * @details This function finalizes a symmetric cipher stream. After this function was called not further updates can be made.
 * Potential padding may be applied. This function does not allocate the buffer.
 * 
 * @param[in] stream_handle Stream handle
 * @param[out] out Where to store the final data
 * @param[out] bytes_encrypted Optional: length of final data
 * @return int Returns 1 for success and 0 for failure
 * @pre stream_handle needs to be created by cw_sym_cipher_stream_create_handle
 */
int cw_sym_cipher_stream_final(CIPHER_STREAM_HANDLE stream_handle, uint8_t *out, int *bytes_encrypted);

/**
 * @brief Deletes a cipher stream handle
 * 
 * @param[in] stream_handle cipher stream handle which is to be deleted
 */
void cw_sym_cipher_stream_delete_handle(CIPHER_STREAM_HANDLE stream_handle);


/**
 * @brief Return the required size of a key for a given algorithm
 * 
 * @param[in] algorithm_id Symmetric cipher algorithm
 * @return int Returns the size of the key
 */
int cw_sym_cipher_get_key_length(cw_symmetric_cipher_algorithm algorithm_id);

/**
 * @brief Return the required size of the initialization vector for a given algorithm
 * 
 * @param[in] algorithm_id Symmetric cipher algorithm
 * @return int Returns the size of the initialization vector
 */
int cw_sym_cipher_get_iv_length(cw_symmetric_cipher_algorithm algorithm_id);

/**
 * @brief Returns the size of a ciphertext based on the used algorithm and plaintext length
 * 
 * @param[in] algorithm_id algorithm to use for encryption
 * @param[in] plaintext_len Plaintext length
 * @return uint64_t ciphertext length after encryption
 */
uint64_t cw_sym_cipher_get_cipher_size(cw_symmetric_cipher_algorithm algorithm_id, const uint64_t plaintext_len);

/**
 * @brief Generate random bytes which can be used for symmetric key encryption
 * 
 * @param[in] algorithm_id
 * @param[in] key_len 
 * @return uint8_t* Random key
 */
uint8_t *cw_sym_cipher_generate_symmetric_key(cw_symmetric_cipher_algorithm algorithm_id, int *key_len);

#endif