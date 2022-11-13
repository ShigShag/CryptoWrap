/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file error.h
 * @author Shig Shag
 * @brief Error interface to retrieve error messages and codes
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef ERROR_H
#define ERROR_H

#include <stdio.h>
#include <stdint.h>

/**
 * @brief Get the last error id
 * Error gets removed from the stack
 * 
 * @return Error id or 0 if no error exists
 */
int cw_error_get_last_error_id();

/**
 * @brief Get the last error id
 * @details Optional parameter can be used to retrieve OpenSSL error code
 * Error gets removed from the stack
 * 
 * @param[out] openssl_error_code Where to save the OpenSSL error code
 * @return Error id or 0 if no error exists
 */
int cw_error_get_last_error_id_ex(uint64_t *openssl_error_code);

/**
 * @brief Get the last CryptoWrap error as a string
 * @details Return value must not be freed
 * Error gets removed from the stack
 * 
 * @return const char* Returns the error string of the last error
 */
const char *cw_error_get_last_error_str();

/**
 * @brief Get the last CryptoWrap and OpenSSL error as an expanded string.
 * @details String is allocated and needs to be freed
 * Error gets removed from the stack
 * 
 * @param[out] out_len Length of the returned string
 * @return char* Returns the expanded error string
 */
char *cw_error_get_last_error_str_ex(uint32_t *out_len);

/**
 * @brief Get the last CryptoWrap error as a string
 * String is being written to a file pointer
 * Error gets removed from the stack
 * 
 * @param[in] fp File pointer to receive the error string
 */
void cw_error_get_last_error_fp(FILE *fp);

/**
* @brief Get the last CryptoWrap and OpenSSL error as an expanded string
 * String is being written to a file pointer
 * Error gets removed from the stack
 * 
 * @param[in] fp File pointer to receive the error string
 */
void cw_error_get_last_error_fp_ex(FILE *fp);

/**
 * @brief Get the last error id
 * Error is not removed from the stack
 * 
 * @return Error id or 0 if no error exists
 */
int cw_error_peak_last_error_id();

/**
 * @brief Get the last error id
 * @details Optional parameter can be used to retrieve OpenSSL error code
 * Error is not removed from the stack
 * 
 * @param[out] openssl_error_code Where to save the OpenSSL error code
 * @return Error id or 0 if no error exists
 */
int cw_error_peak_last_error_id_ex(uint64_t *openssl_error_code);

/**
 * @brief Get the last CryptoWrap error as a string
 * @details Return value must not be freed
 * Error is not removed from the stack
 * 
 * @return const char* Returns the error string of the last error
 */
const char *cw_error_peak_last_error_str();

/**
 * @brief Get the last CryptoWrap and OpenSSL error as an expanded string.
 * @details String is allocated and needs to be freed
 * Error is not removed from the stack
 * 
 * @param[out] out_len Length of the returned string
 * @return char* Returns the expanded error string
 */
char *cw_error_peak_last_error_str_ex(uint32_t *out_len);

/**
 * @brief Get the last CryptoWrap error as a string
 * String is being written to a file pointer
 * Error is not removed from the stack
 * 
 * @param[in] fp File pointer to receive the error string
 */
void cw_error_peak_write_fp(FILE *fp);

/**
* @brief Get the last CryptoWrap and OpenSSL error as an expanded string
 * String is being written to a file pointer
 * Error is not removed from the stack
 * 
 * @param[in] fp File pointer to receive the error string
 */
void cw_error_peak_write_fp_ex(FILE *fp);

/**
 * @brief Get the CryptoWrap string from a CryptWrap error id
 * 
 * @param[in] error_id Error id of the associated string
 * @return const char* Error string associated to the id
 */
const char *cw_error_get_str_from_id(int error_id);

#endif