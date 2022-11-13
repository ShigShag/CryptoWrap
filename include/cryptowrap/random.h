/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

/**
 * @file random.h
 * @author Shig Shag
 * @brief Random number generation
 * @version 0.1
 * @date 2022-11-01
 *
 * @copyright Copyright (c) 2022 Leon Weinmann
 *
 */

#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

/**
 * @brief Random uint8_t
 *
 * @param[in] num_ptr Pointer to a uint8_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_uint8_t(uint8_t *num_ptr);

/**
 * @brief Random uint16_t
 *
 * @param[in] num_ptr Pointer to a uint16_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_uint16_t(uint16_t *num_ptr);

/**
 * @brief Random uint32_t
 *
 * @param[in] num_ptr Pointer to a uint32_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_uint32_t(uint32_t *num_ptr);

/**
 * @brief Random uint64_t
 *
 * @param[in] num_ptr Pointer to a uint64_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_uint64_t(uint64_t *num_ptr);

/**
 * @brief Random int8_t
 *
 * @param[in] num_ptr Pointer to a random int8_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_int8_t(int8_t *num_ptr);

/**
 * @brief Random int16_t
 *
 * @param[in] num_ptr Pointer to a random int16_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_int16_t(int16_t *num_ptr);

/**
 * @brief Random int32_t
 *
 * @param[in] num_ptr Pointer to a random int32_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_int32_t(int32_t *num_ptr);

/**
 * @brief Random int64_t
 *
 * @param[in] num_ptr Pointer to a random int64_t var
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_int64_t(int64_t *num_ptr);

/**
 * @brief Generate a random number.
 * This Makro can be used for automatic calling for a suitable function
 *
 */
#define CW_RANDOM_NUMBER(num_ptr) _Generic(num_ptr,              \
                                        uint8_t *             \
                                        : cw_random_uint8_t,  \
                                          uint16_t *          \
                                        : cw_random_uint16_t, \
                                          uint32_t *          \
                                        : cw_random_uint32_t, \
                                          uint64_t *          \
                                        : cw_random_uint64_t, \
                                          int8_t *            \
                                        : cw_random_int8_t,   \
                                          int16_t *           \
                                        : cw_random_int16_t,  \
                                          int32_t *           \
                                        : cw_random_int32_t,  \
                                          int64_t *           \
                                        : cw_random_int64_t)(num_ptr)

/**
 * @brief Random bytes are not allocated within the function
 *
 */
#define RANDOM_NO_ALLOC 0x00000001

/**
 * @brief Generate random bytes
 *
 * @param[out] buffer Where to store the random bytes
 * @param[in] len Desired length of random bytes
 * @param[in] flags
 *    - RANDOM_NO_ALLOC Bytes are not allocated within the function
 * @return int Returns 1 if verification was successful and 0 for failure
 */
int cw_random_bytes(uint8_t **buffer, const uint64_t len, const uint8_t flags);

#endif