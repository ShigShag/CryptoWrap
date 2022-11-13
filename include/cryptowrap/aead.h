/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file aead.h
 * @author Shig Shag
 * @brief Authenticated encryption or decryption
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Algorithm which can be used for
 * aead operations.
 * 
 */
typedef enum
{
    CW_AES_128_GCM,
    CW_AES_192_GCM,
    CW_AES_256_GCM,
    CW_ARIA_128_GCM,
    CW_ARIA_192_GCM,
    CW_ARIA_256_GCM,

    CW_AES_128_CCM,
    CW_AES_192_CCM,
    CW_AES_256_CCM,
    CW_ARIA_128_CCM,
    CW_ARIA_192_CCM,
    CW_ARIA_256_CCM,

    CW_AES_128_OCB,
    CW_AES_192_OCB,
    CW_AES_256_OCB,

    CW_CHACHA_20_POLY_1305
} aead_mode;

/**
 * @brief Do not allocated output and tag when encrypting
 * 
 */
#define AEAD_NO_ALLOC 0x00000001

/**
 * @brief Do not allocated output
 * 
 */
#define AEAD_OUT_NO_ALLOC 0x00000002

/**
 * @brief Do not allocated Tag when encrypting
 * 
 */
#define AEAD_TAG_NO_ALLOC 0x00000004

/**
 * @brief Encrypt data with aead
 * @details This function encrypts data with aead. For in place encryption pass the same Variable to plaintext and ciphertext
 * and set the Flag AEAD_OUT_NO_ALLOC.
 *
 * @param[in] plaintext Plaintext to be encrypted
 * @param[in] plaintext_len Plaintext length
 * @param[out] ciphertext  Where to write the encrypted plaintext.
 * @param[out] ciphertext_len optional: Where to write the length of the ciphertext
 * @param[in] key Key for encryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] aad Additional data
 * @param[in] aad_len Additional data length
 * @param[out] tag Where to save the generated Tag
 * @param[in] tag_len Desired tag length
 * @param[in] algorithm_id Algorithm for encryption
 * @param[in] flags Flags
 *  - AEAD_NO_ALLOC Do not allocate ciphertext or tag
 *  - AEAD_OUT_NO_ALLOC Do not allocate ciphertext
 *  - AEAD_TAG_NO_ALLOC Do not allocated tag
 * @return int Returns 1 for success and 0 for failure
 */
int cw_aead_raw_encrypt_bytes(const uint8_t *plaintext, const size_t plaintext_len, uint8_t **ciphertext, size_t *ciphertext_len,
                              const uint8_t *key, const int key_len,
                              const uint8_t *iv, const int iv_len,
                              const uint8_t *aad, const uint32_t aad_len,
                              uint8_t **tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags);

/**
 * @brief Decrypt data with aead
 * @details This function decrypts data with aead. For in place decryption pass the same Variable to ciphertext and plaintext
 * and set the Flag AEAD_OUT_NO_ALLOC.
 *
 * @param[in] ciphertext Ciphertext to be decrypted
 * @param[in] ciphertext_len Ciphertext len
 * @param[out] plaintext Where the decrypted ciphertext.
 * @param[out] plaintext_len optional: Where to write the decrypted ciphertext length
 * @param[in] key  Key for decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] aad Additional data
 * @param[in] aad_len Additional data length
 * @param[in] tag Tag which was generated when encrypting the data
 * @param[in] tag_len Tag length
 * @param[in] algorithm_id Algorithm for decryption
 * @param[in] flags Flags
 *  - AEAD_NO_ALLOC Do not allocate plaintext or tag
 *  - AEAD_OUT_NO_ALLOC Do not allocate plaintext
 *  - AEAD_TAG_NO_ALLOC Do not allocated tag
 * @return int Returns 1 for success and 0 for failure
 * @pre Tag needs to be obtained from encryption
 */
int cw_aead_raw_decrypt_bytes(const uint8_t *ciphertext, const uint64_t ciphertext_len, uint8_t **plaintext, uint64_t *plaintext_len,
                              const uint8_t *key, const int key_len,
                              const uint8_t *iv, const int iv_len,
                              const uint8_t *aad, const uint32_t aad_len,
                              uint8_t *tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags);

/**
 * @brief Encrypt a file with aead
 * @details To crypt a file in place set out_file to NULL.
 *
 * @param[in, out] in_file File which contents should be encrypted
 * @param[out] out_file Where to write the ciphertext
 * @param[in] key Key for encryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] aad Additional data
 * @param[in] aad_len Additional data length
 * @param[out] tag Where to save the generated Tag
 * @param[in] tag_len Desired tag length
 * @param[in] algorithm_id Algorithm for encryption
 * @param[in] flags Flags
 *  - AEAD_NO_ALLOC Do not allocate ciphertext or tag
 *  - AEAD_OUT_NO_ALLOC Do not allocate ciphertext
 *  - AEAD_TAG_NO_ALLOC Do not allocated tag
 * @return int Returns 1 for success and 0 for failure
 */
int cw_aead_file_encrypt(const char *in_file, const char *out_file,
                         const uint8_t *key, const uint32_t key_len,
                         const uint8_t *iv, const uint32_t iv_len,
                         const uint8_t *aad, uint32_t aad_len,
                         uint8_t **tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags);

/**
 * @brief Decrypt a file with aead
 * @details To decrypt a file in place set out_file to NULL.
 *
 * @param[in, out] in_file File which contents should be decrypted
 * @param[out] out_file Where to write the plaintext
 * @param[in] key Key for decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] aad Additional data
 * @param[in] aad_len Additional data length
 * @param[in] tag Tag which was generated when encrypting the data
 * @param[in] tag_len Tag length
 * @param[in] algorithm_id Algorithm for decryption
 * @param[in] flags Flags
 *  - AEAD_NO_ALLOC Do not allocate ciphertext or tag
 *  - AEAD_OUT_NO_ALLOC Do not allocate ciphertext
 *  - AEAD_TAG_NO_ALLOC Do not allocated tag
 * @return int Returns 1 for success and 0 for failure
 * @pre Tag needs to be obtained from encryption
 */
int cw_aead_file_decrypt(const char *in_file, const char *out_file, const uint8_t *key, int key_len,
                         const uint8_t *iv, const uint32_t iv_len,
                         const uint8_t *aad, const uint32_t aad_len,
                         uint8_t *tag, const int tag_len, aead_mode algorithm_id, const uint8_t flags);

/* Stream */

/**
 * @brief Set stream mode to encryption
 * 
 */
#define AEAD_STREAM_ENCRYPT 1

/**
 * @brief Set stream mode to decryption
 * 
 */
#define AEAD_STREAM_DECRYPT 0

/**
 * @brief Aead stream handle which can be used for updating and finalizing a stream
 * 
 */
typedef void *AEAD_STREAM_HANDLE;

/**
 * @brief Create a stream handle for aead
 * @details A stream handle can be used to en- or decrypt data from continuous data streams.
 * Encryption or decryption may be set with mode.
 *
 * @param[out] pstream_handle Where to save the stream handle
 * @param[in] key Key for encryption or decryption
 * @param[in] key_len Key length
 * @param[in] iv Initialization vector
 * @param[in] iv_len Initialization vector length
 * @param[in] aad Additional data
 * @param[in] aad_len Additional data length
 * @param[in] algorithm_id Which algorithm to use for encryption or decryption
 * @param[in] mode Encryption or Decryption
 *      - AEAD_STREAM_ENCRYPT for encryption
 *      - AEAD_STREAM_DECRYPT for decryption
 * @return int Returns 1 for success and 0 for failure
 */
int cw_aead_stream_create_handle(AEAD_STREAM_HANDLE *pstream_handle,
                                 const uint8_t *key, const uint32_t key_len,
                                 const uint8_t *iv, const uint32_t iv_len,
                                 const uint8_t *aad, const uint32_t aad_len,
                                 aead_mode algorithm_id, const int mode);

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
 * @pre stream_handle needs to be created by cw_aead_stream_create_handle
 */
int cw_aead_stream_update(const AEAD_STREAM_HANDLE stream_handle,
                          uint8_t *out, int *bytes_processed,
                          const uint8_t *in, const int in_len);

/**
 * @brief Finalize a aead stream
 * @details This function finalizes an aead stream. After this function was called not further updates can be made.
 * Potential padding may be applied. This function does not allocate the buffer.
 * 
 * @param[in] stream_handle Stream handle
 * @param[out] out Where to store the final data
 * @param[out] bytes_processed Optional: length of final data
 * @param[in, out] tag 
 *      - If encrypting: Where to save the tag
 *      - If decrypting: Tag which was created by encryption
 * @param[in] tag_len 
 *      - If encrypting: Desired length of the tag
 *      - If decrypting: Tag length created with encryption
 * @param[in] flags
 *  - AEAD_NO_ALLOC Do not allocate tag
 *  - AEAD_TAG_NO_ALLOC Do not allocated tag
 * @return int Returns 1 for success and 0 for failure
 * @pre stream_handle needs to be created by cw_aead_stream_create_handle
 */
int cw_aead_stream_final(const AEAD_STREAM_HANDLE stream_handle,
                         uint8_t *out, int *bytes_processed,
                         uint8_t **tag, const int tag_len, const uint8_t flags);

/**
 * @brief Deletes a stream handle
 * 
 * @param[in] stream_handle Handle which is to be deleted
 * @pre stream_handle needs to be created by cw_aead_stream_create_handle
 */
void cw_aead_stream_delete_handle(AEAD_STREAM_HANDLE stream_handle);

/**
 * @brief Returns the required size of the key for a given algorithm_id
 * 
 * @param[in] algorithm_id Algorithm id for which to return the required key length
 * @return int Returns the required key length
 */
int cw_aead_get_key_length(aead_mode algorithm_id);

/**
 * @brief Returns the required size of the iv for a given algorithm_id
 * 
 * @param[in] algorithm_id Algorithm id for which to return the required iv length
 * @return int Returns the required iv length
 */
int cw_aead_get_iv_length(aead_mode algorithm_id);

/**
 * @brief Returns the size of a ciphertext based on the used algorithm and plaintext length
 * 
 * @param[in] plaintext_len Plaintext length
 * @return uint64_t ciphertext length after encryption
 */
uint64_t cw_aead_get_encrypt_size(uint64_t plaintext_len);

#endif  