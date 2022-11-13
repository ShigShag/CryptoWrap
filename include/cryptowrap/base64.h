/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file base64.h
 * @author Shig Shag
 * @brief Base 64 Encoding and Decoding
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef BASE64_H
#define BASE64_H

#include <stdint.h>

/**
 * @brief Do not allocated output
 * 
 */
#define BASE64_NO_ALLOC 0x00000001

/**
 * @brief Base64 encode a byte sequence
 * @details In place encoding is not possible
 * 
 * @param[in] plaintext Byte sequence to encode
 * @param[in] plaintext_len Length of byte sequence
 * @param[out] encoded Where to store the encoded sequence
 * @param[out] encoded_len Optional: Where to store the encoded length
 * @param[in] flags 
 *      - BASE64_NO_ALLOC Do not allocate the encoded text
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_raw_encode(const uint8_t *plaintext, const uint64_t plaintext_len, uint8_t **encoded, uint64_t *encoded_len, const uint8_t flags);

/**
 * @brief Base64 decode a encoded byte sequence
 * @details In place decoding is not possible
 * 
 * @param[in] encoded Byte sequence to decode
 * @param[in] encoded_len Length of byte sequence
 * @param[out] plaintext Where to store the decoded sequence
 * @param[out] plaintext_len Optional: Where to store the decoded length
 * @param[in] flags 
 *      - BASE64_NO_ALLOC Do not allocate the encoded text
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_raw_decode(const uint8_t *encoded, const uint64_t encoded_len, uint8_t **plaintext, uint64_t *plaintext_len, const uint8_t flags);

/**
 * @brief Base64 stream for encoding
 * 
 */
#define BASE64_STREAM_ENCODE 1

/**
 * @brief Base64 stream for decoding
 * 
 */
#define BASE64_STREAM_DECODE 0

/**
 * @brief Type to store a stream handle which can be used for updating and finalizing a stream
 * 
 */
typedef void *BASE64_STREAM_HANDLE;

/**
 * @brief Initialize a base64 encode or decode stream
 * 
 * @param[out] p_stream_handle Where to store the stream handle
 * @param[in] mode Which mode to use:
 *      - BASE64_STREAM_ENCODE for encoding
 *      - BASE64_STREAM_DECODE for decoding
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_stream_init(BASE64_STREAM_HANDLE *p_stream_handle, int mode);

/**
 * @brief Update a stream handle with data 
 * @details This function can be called multiple times to encode or decode more data. 
 * This function does not allocate the buffer.
 * 
 * @param[in] stream_handle Stream handle
 * @param[out] out Where to store the processed bytes
 * @param[out] out_len Where to store the processed bytes length
 * @param[in] in 
 * @param[in] in_len 
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_stream_update(BASE64_STREAM_HANDLE stream_handle, uint8_t *out, int *out_len, const uint8_t *in, const int in_len);

/**
 * @brief Finalize a stream
 * @details This function finalizes an encode or decode stream. After this function was called not further updates can be made.
 * 
 * @param[in] stream_handle Stream handle
 * @param[out] out Where to store the processed bytes
 * @param[out] out_len Optional: Where to store the processed bytes length
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_stream_final(BASE64_STREAM_HANDLE stream_handle, uint8_t *out, int *out_len);

/**
 * @brief Deletes a stream handle
 * 
 * @param[in] stream_handle Stream handle to delete
 */
void cw_base64_stream_delete(BASE64_STREAM_HANDLE stream_handle);

/**
 * @brief Base64 encode file contents
 * @details in place encoding is not allowed
 * 
 * @param[in] in_file File which contents are to be encoded
 * @param[in] out_file File in which to store the encoded text
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_file_encode(const char *in_file, const char *out_file);

/**
 * @brief Base64 decode file contents
 * @details in place decoding is not allowed
 * 
 * @param[in] in_file File which contents are to be decoded
 * @param[in] out_file 
 * @return int Returns 1 for success and 0 for failure
 */
int cw_base64_file_decode(const char *in_file, const char *out_file);

/**
 * @brief Base64 encode file contents
 * 
 * @param[in] in_file File which contents are to be encoded
 * @param[out] out Where to save the encoded contents
 * @param[out] out_len Optional: Where to save the encoded contents length
 * @param[in] flags 
 *      - BASE64_NO_ALLOC Do no allocate the encoded contents
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_base64_file_encode_out(const char *in_file, uint8_t **out, uint64_t *out_len, const uint8_t flags);

/**
 * @brief Base64 decode file contents
 * 
 * @param[in] in_file File which contents are to be decoded
 * @param[out] out Where to save the decoded contents
 * @param[out] out_len Optional: Where to save the decoded contents length
 * @param[in] flags 
 *      - BASE64_NO_ALLOC Do no allocate the decoded contents
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_base64_file_decode_out(const char *in_file, uint8_t **out, uint64_t *out_len, const uint8_t flags);

#endif

