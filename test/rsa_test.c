/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <criterion/new/assert.h>

#include <internal/fetching.h>
#include <internal/unit_test/cw_uint_test_internal.h>

#include <internal/rsa_internal.h>

#include <cryptowrap/error.h>

#define RSA_UNIT_TEST(func_call, fail_condition, end_point, function_str)   \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s\n", \
                           function_str)

#define RSA_UNIT_TEST_SUPPOSE_FAIL(func_call, fail_condition, end_point, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s\n",            \
                           function_str)

#define RSA_UNIT_TEST_VECTOR_SIZE(func_call, fail_condition, end_point, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- vector_size: %d\n",    \
                           function_str, vector_size)

#define RSA_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(func_call, fail_condition, end_point, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- vector_size: %d\n",                 \
                           function_str, vector_size)

uint8_t test_vector[] = {
    0xF6, 0xEB, 0x67, 0x43, 0xCA, 0x21, 0x18, 0x95, 0xB6, 0x14, 0x9F, 0x62,
    0x39, 0x1B, 0xE8, 0x44, 0x5E, 0x7B, 0x86, 0x3B, 0x75, 0x3A, 0x48, 0xBD,
    0x79, 0x6A, 0xC7, 0x6D, 0x16, 0xD9, 0xCE, 0xD8, 0x7A, 0x2D, 0x59, 0x76,
    0xAC, 0x86, 0xCB, 0xB2, 0x1A, 0xE6, 0x62, 0x21, 0xE4, 0x48, 0x11, 0x6F,
    0xD0, 0xE6, 0x73, 0x8E, 0x36, 0xC9, 0x7B, 0x00, 0x72, 0x5C, 0x97, 0x0A,
    0x9F, 0x1D, 0xD4, 0xEE, 0x27, 0x53, 0xCD, 0xB1, 0xD4, 0x81, 0xF1, 0xF6,
    0xE1, 0xE1, 0x18, 0x0D, 0x3D, 0xA8, 0x4C, 0xA9, 0xD3, 0xCF, 0x0B, 0x0C,
    0x39, 0xE3, 0x29, 0xE2, 0x7A, 0xB1, 0x02, 0x43, 0x9A, 0x55, 0x62, 0xFD,
    0x2A, 0x1A, 0x2A, 0xDC, 0xE5, 0x3D, 0x40, 0xDA, 0x2E, 0x77, 0x94, 0x01,
    0x0E, 0x4A, 0x45, 0x29, 0xF4, 0xED, 0xBD, 0x8B, 0xDF, 0x16, 0x71, 0x16,
    0x48, 0xFF, 0xD2, 0x1A, 0xFF, 0xA7, 0x1F, 0xAE, 0xCD, 0xE2, 0x9E, 0x46,
    0x5F, 0x51, 0x61, 0x2C, 0x30, 0x8E, 0xEC, 0xE2, 0x5E, 0x3F, 0xD3, 0x87,
    0x30, 0xF8, 0xAC, 0x0A, 0x86, 0x5E, 0xA7, 0x98, 0x88, 0x20, 0x0F, 0xC1,
    0xD9, 0xF0, 0xB9, 0x31, 0x90, 0xEA, 0xD2, 0xC2, 0x6E, 0xC7, 0x21, 0x39,
    0x6A, 0xD7, 0xA7, 0x17, 0x4A, 0x21, 0x3B, 0xEB, 0x8B, 0xBC, 0xB7, 0x14,
    0x85, 0x3B, 0xF6, 0x0A, 0xA2, 0xA4, 0xF0, 0x0A, 0x29, 0x46, 0xCE, 0x53,
    0xA7, 0x7F, 0x55, 0xAF, 0xA0, 0x7F, 0x46, 0x25, 0xE5, 0x42, 0x67, 0x35,
    0xC1, 0xC2, 0x32, 0x1F, 0xEF, 0x20, 0x2E, 0x06, 0xA2, 0xB1, 0x69, 0xF3,
    0x04, 0x40, 0xB8, 0xE4, 0x2D, 0x49, 0xD7, 0x58, 0xEF, 0x51, 0x02, 0xB6,
    0xCB, 0xD9, 0x69, 0x3F, 0x13, 0xD4, 0xD7, 0x5E, 0x2A, 0xD6, 0xE5, 0x6F,
    0xA3, 0x1A, 0x9D, 0xEF, 0xE0, 0x31, 0xFF, 0x96, 0x02, 0x8F, 0x9D, 0x70,
    0xA0, 0xCF, 0x2D, 0xA2, 0xF2, 0x1D, 0x84, 0xD4, 0xFB, 0xAD, 0xA7, 0x7A,
    0x9A, 0xA6, 0xEE, 0xD1, 0xEF, 0x26, 0x22, 0xFA, 0x72, 0x9A, 0xA8, 0x2F,
    0x5E, 0x57, 0xB5, 0x86, 0x96, 0x86, 0x3E, 0x95, 0xFA, 0xFA, 0x1D, 0x99,
    0x16, 0x32, 0x41, 0xD4, 0xA4, 0x20, 0x2D, 0xB8, 0x12, 0x80, 0x3F, 0x2B,
    0x8F, 0xE8, 0x67, 0x4A, 0x1E, 0x8D, 0xC3, 0x76, 0xE7, 0xFA, 0x44, 0xB0,
    0x00, 0x87, 0xFA, 0xE5, 0x3E, 0xDB, 0x06, 0x90, 0x03, 0xA0, 0x32, 0x25,
    0x08, 0xB2, 0x22, 0x9B, 0x41, 0x27, 0xAE, 0xEC, 0xE5, 0xAB, 0x44, 0x55,
    0xAD, 0x7C, 0xE5, 0xC0, 0xAF, 0x2C, 0x93, 0x81, 0xC8, 0xDC, 0x45, 0x3F,
    0x14, 0xCA, 0x25, 0x5B, 0x7A, 0x23, 0x0A, 0xAC, 0xC4, 0xD0, 0x79, 0xB7,
    0x43, 0x8E, 0x19, 0x86, 0x1F, 0x10, 0xA3, 0x09, 0x34, 0xF1, 0x5A, 0xDC,
    0x61, 0xC2, 0x6A, 0x8C, 0xB1, 0x8A, 0xC9, 0xAF, 0x0B, 0x3D, 0x2F, 0x70,
    0xCB, 0x99, 0x06, 0x72, 0x95, 0x51, 0x00, 0x68, 0xF7, 0x8C, 0x8D, 0xAF,
    0xD0, 0x49, 0x1E, 0x11, 0x81, 0x80, 0xD6, 0x1E, 0xD6, 0x7A, 0xF2, 0x60,
    0xB0, 0xDC, 0xFC, 0x07, 0x07, 0x3C, 0x97, 0x58, 0x49, 0xFE, 0x0E, 0x15,
    0xD7, 0xB0, 0x03, 0xB9, 0x9D, 0x24, 0xF0, 0x09, 0x01, 0xD0, 0xA8, 0x0C,
    0xDD, 0x36, 0x3F, 0xFD, 0x51, 0xB4, 0x9E, 0x49, 0x0F, 0xB5, 0xAB, 0x8E,
    0x17, 0xDF, 0x46, 0xF5, 0x1E, 0x82, 0x27, 0xB5, 0xF4, 0x36, 0x6F, 0xBB,
    0xEB, 0xC5, 0x69, 0xBB, 0x61, 0x0C, 0x7E, 0x7D, 0x0B, 0xC3, 0x9F, 0x49,
    0x38, 0x5F, 0x31, 0xE9, 0x71, 0x50, 0x46, 0x8B, 0x68, 0xA8, 0x76, 0x87,
    0x80, 0xB8, 0xAE, 0xC8, 0xA0, 0xFA, 0x4C, 0xF8, 0xBB, 0x07, 0x1A, 0x2E,
    0x8E, 0x46, 0x00, 0xB6, 0x52, 0xCC, 0x0F, 0x82, 0x38, 0xEC, 0x9D, 0x3A,
    0xE0, 0x24, 0xF6, 0x0F, 0x50, 0xC9, 0x69, 0xCF, 0x15, 0x41, 0xE3, 0xF6,
    0xC5, 0xAC, 0xEC, 0xD6, 0x25, 0x42, 0xBE, 0xCA, 0x0C, 0x4C, 0xD8, 0x21,
    0xAA, 0x56, 0xBB, 0x01, 0x26, 0xBC, 0x0F, 0x6A, 0xBA, 0x0C, 0xBA, 0x7E,
    0x06, 0x55, 0xB1, 0xA9, 0x67, 0x1F, 0xCC, 0xB3, 0xC8, 0xC0, 0xCE, 0xAF,
    0xE0, 0x42, 0xAB, 0x3C, 0x7B, 0x1C, 0xF8, 0x7F, 0xF2, 0x92, 0xB2, 0xAA,
    0x46, 0xCA, 0xD8, 0x1B, 0xB5, 0x4E, 0xDA, 0xBC, 0x47, 0x81, 0x5A, 0x3A,
    0xDF, 0xCE, 0xD2, 0xD5, 0x31, 0x39, 0xDE, 0x02, 0x1E, 0x2E, 0x3B, 0x82,
    0x36, 0x80, 0x76, 0x09, 0x45, 0xAC, 0x7A, 0x86, 0x8F, 0x21, 0xA5, 0x98,
    0x2D, 0xFE, 0x07, 0x4C, 0x6E, 0x9E, 0x21, 0xE5, 0x5C, 0x85, 0x72, 0x7E,
    0x76, 0xFB, 0x86, 0x79, 0x6F, 0xBB, 0x3F, 0x61, 0xC0, 0x14, 0x9E, 0xAE,
    0xE4, 0xB1, 0x09, 0x62, 0x42, 0xF4, 0x91, 0xE3, 0xF9, 0xD2, 0x16, 0x68,
    0x92, 0x46, 0x9F, 0x97, 0x2C, 0xA8, 0xB8, 0xE0, 0x8D, 0x25, 0xA4, 0xEF,
    0xB4, 0x5B, 0x65, 0xAE, 0x85, 0xF2, 0x55, 0xAB, 0x0D, 0xD5, 0x9B, 0x20,
    0x1B, 0xFA, 0x6A, 0x3C, 0xD1, 0x69, 0x0A, 0x81, 0x56, 0x47, 0xA3, 0xCA,
    0xA9, 0x52, 0xD0, 0x4F, 0xCC, 0x7A, 0x23, 0x52, 0x01, 0xC9, 0xF8, 0xF0,
    0xB4, 0x73, 0x6A, 0xD3, 0x01, 0x36, 0x62, 0xF6, 0xDE, 0x3E, 0x35, 0x33,
    0xB0, 0x92, 0x6B, 0x28, 0xF1, 0xC7, 0x41, 0xE0, 0x70, 0x6E, 0xBA, 0x4B,
    0x38, 0x91, 0xD6, 0x00, 0xD2, 0x26, 0xDC, 0xBC, 0xB0, 0x68, 0xFE, 0x4C,
    0x0E, 0x02, 0xDF, 0xAD, 0x6B, 0x88, 0xBD, 0x8B, 0xCB, 0x3C, 0x32, 0x61,
    0xC3, 0x58, 0x0E, 0x51, 0x5F, 0x9B, 0xD9, 0x38, 0xEE, 0x29, 0x4D, 0x31,
    0xD4, 0xC0, 0xB6, 0x47, 0xA4, 0xDE, 0xE4, 0xD0, 0x77, 0x48, 0xAA, 0x05,
    0xA9, 0x30, 0x30, 0x71, 0xEE, 0xAD, 0xB5, 0x44, 0x10, 0x38, 0x13, 0x32,
    0xF5, 0xA8, 0xD4, 0x96, 0x7C, 0x8B, 0x51, 0x8B, 0xF3, 0x22, 0x1D, 0x51,
    0xDC, 0xFA, 0x8A, 0x94, 0xD6, 0xE0, 0x14, 0x50, 0xC8, 0x5D, 0xD7, 0x37,
    0x8A, 0x67, 0xDA, 0x54, 0x1C, 0xAE, 0x22, 0x4D, 0x79, 0x7D, 0x27, 0x63,
    0xD0, 0x00, 0xD6, 0x34, 0xF4, 0x92, 0xC0, 0x8F, 0x54, 0xB1, 0x41, 0x86,
    0x1D, 0xCF, 0x69, 0x37, 0x1C, 0x03, 0x83, 0x98, 0x65, 0xF4, 0xA0, 0xF1,
    0x86, 0x00, 0x9A, 0x53, 0xF8, 0x1A, 0x62, 0xD2, 0x42, 0xD8, 0x54, 0x5A,
    0x78, 0x8E, 0xDA, 0x98, 0x85, 0xBF, 0x1B, 0x94, 0x5D, 0x98, 0xFC, 0x6D,
    0x87, 0x66, 0x93, 0x1A, 0x0C, 0x92, 0x3A, 0x34, 0x13, 0xB4, 0x20, 0x32,
    0xD1, 0xB2, 0x69, 0x28, 0x51, 0xB5, 0x3B, 0x9B, 0xFA, 0x54, 0x79, 0xC4,
    0xFF, 0x02, 0xB2, 0xD2, 0x57, 0x23, 0xF8, 0x22, 0xEC, 0x7D, 0x17, 0x43,
    0x15, 0x3F, 0xE3, 0x15, 0x0A, 0x26, 0x76, 0x28, 0x53, 0xBD, 0xB4, 0x8E,
    0x01, 0xBB, 0x50, 0xD9, 0x91, 0x0B, 0xFF, 0x31, 0x74, 0x5B, 0x62, 0xA2,
    0x80, 0x7F, 0x05, 0xC5, 0xDA, 0xD7, 0x12, 0xD2, 0x8E, 0x32, 0xEA, 0x06,
    0x5A, 0xEE, 0x1D, 0xDF, 0x7C, 0xF1, 0x25, 0xD1, 0xAD, 0x1F, 0xA2, 0xF6,
    0xC0, 0xDB, 0x6F, 0x11, 0xB5, 0x73, 0x77, 0x60, 0x38, 0x38, 0x4B, 0x6A,
    0x7A, 0xFB, 0x7F, 0x16, 0x6E, 0x34, 0x29, 0xD9, 0x4F, 0x5D, 0x55, 0x8B,
    0xBE, 0x04, 0x44, 0xEC, 0x47, 0x9B, 0xDE, 0xFD, 0x7F, 0x5D, 0x9F, 0x8E,
    0x8C, 0xA6, 0xF5, 0x56, 0x6B, 0x06, 0x64, 0x64, 0x43, 0xD3, 0x5B, 0x61,
    0x13, 0x07, 0x25, 0x69, 0x5F, 0xA8, 0x97, 0xBC, 0x18, 0x24, 0x15, 0xA8,
    0x92, 0x2A, 0xC6, 0xC1, 0xE2, 0x5C, 0x8E, 0xCE, 0xE8, 0xD1, 0x66, 0x13,
    0xA3, 0x82, 0xB9, 0x5E, 0xC3, 0x38, 0xEE, 0x14, 0xB4, 0xF0, 0x0B, 0x6D,
    0x74, 0x4C, 0x99, 0xFF, 0x5F, 0x86, 0x1F, 0x69, 0x1E, 0xD1, 0x53, 0xFD,
    0xB4, 0x26, 0x8F, 0x45, 0x3D, 0xE3, 0x46, 0x5D, 0x46, 0x45, 0x32, 0x7F,
    0xDA, 0xA4, 0xB7, 0x8C, 0xC1, 0xAA, 0x84, 0xA2, 0x31, 0xE7, 0xE0, 0xCB,
    0x81, 0x59, 0xE8, 0xD9, 0x19, 0xF5, 0xDD, 0x6A, 0x1E, 0xB2, 0xDF, 0x8E,
    0xF7, 0x77, 0x1C, 0x9A, 0x07, 0x63, 0x30, 0x0D, 0x81, 0x4F, 0x62, 0xAE,
    0x1C, 0x88, 0x7B, 0x77, 0xAA, 0xF1, 0x65, 0x16, 0x5E, 0x25, 0x57, 0xC2,
    0x70, 0x2E, 0x7C, 0xCA, 0xC2, 0x0B, 0xE5, 0xB5, 0xD5, 0x13, 0xF6, 0x70,
    0x6C, 0xBD, 0x04, 0xCA, 0x10, 0x32, 0x4E, 0x6A, 0x92, 0x47, 0xBA, 0xDF,
    0xAC, 0xDC, 0x83, 0x0F, 0x47, 0xEB, 0xAC, 0x2F, 0x02, 0xC8, 0x39, 0x3D,
    0xF4, 0x87, 0xE5, 0xA1, 0xCC, 0x37, 0x40, 0xCE, 0x17, 0xF1, 0xE6, 0xE1,
    0x0B, 0xF5, 0xF8, 0x71, 0xDA, 0xCD, 0x4C, 0xE6, 0x8D, 0xC3, 0x02, 0x32,
    0xF4, 0x78, 0x2C, 0x45, 0x04, 0x64, 0xAA, 0x65, 0x84, 0xA0, 0x5E, 0xD6,
    0xDC, 0x3A, 0xB6, 0xC5, 0xF2, 0xBC, 0x8D, 0xEB, 0x72, 0xA5, 0x43, 0x32,
    0x0A, 0x85, 0xF4, 0xF5, 0x2E, 0x8C, 0x71, 0x8C, 0xD3, 0xE8, 0x5C, 0xBB,
    0x04, 0xAF, 0x9E, 0x91, 0x6D, 0x38, 0x21, 0xA5, 0x46, 0xF8, 0xF8, 0xC0,
    0xD7, 0x7C, 0x1B, 0xC5, 0xC7, 0x29, 0xE5, 0x7D, 0x8D, 0x32, 0xDA, 0x08,
    0x92, 0x77, 0x8D, 0x1D, 0x70, 0x50, 0xC8, 0x42, 0xAE, 0x7B, 0x20, 0xD2,
    0x7D, 0x0A, 0xC9, 0x63, 0xAF, 0x01, 0xD0, 0x20, 0x69, 0x27, 0xE0, 0x9F,
    0x3D, 0x7E, 0xFD, 0xA8, 0x4D, 0xFE, 0x94, 0xE5, 0x34, 0xBD, 0xB7, 0x10,
    0xFE, 0xCC, 0x42, 0x5C, 0x60, 0xC6, 0x47, 0x73, 0x51, 0xE5, 0xF6, 0xFF,
    0x59, 0x0B, 0x9A, 0x44, 0xE3, 0x65, 0xED, 0x1E, 0x85, 0xA9, 0x37, 0x2D,
    0xBF, 0x12, 0xDB, 0x79, 0x4D, 0xED, 0x8E, 0x18, 0x68, 0x4D, 0xC6, 0xC8,
    0x59, 0xC4, 0xC1, 0x9B, 0x99, 0x03, 0x9C, 0x15, 0x58, 0xC4, 0xD6, 0x17,
    0x90, 0xB4, 0x06, 0xCC, 0xD7, 0x20, 0x20, 0xBE, 0x7C, 0x3D, 0x2F, 0x70,
    0xF6, 0xC6, 0x5E, 0x85, 0xF3, 0x02, 0x53, 0x09, 0xC2, 0xA0, 0xDB, 0xE8,
    0x37, 0xD8, 0xC0, 0x08, 0xF4, 0x12, 0x88, 0xE7, 0x06, 0x1A, 0x4E, 0x8E,
    0xFC, 0x8A, 0x18, 0xBD, 0xC9, 0xAF, 0x2C, 0x39, 0x66, 0x93, 0x8B, 0xA5,
    0xB9, 0xF8, 0xDE, 0xB6, 0x7A, 0x05, 0xB2, 0x5A, 0x3C, 0x31, 0x97, 0x54,
    0xFB, 0x3B, 0x4F, 0x6A, 0x44, 0x6B, 0x3B, 0xCB, 0x29, 0xBF, 0xB3, 0xF5,
    0x42, 0xC3, 0x92, 0xFA, 0x41, 0xAD, 0x84, 0xF9, 0x02, 0x53, 0x2E, 0x4F,
    0x02, 0xCF, 0x19, 0x9D, 0xE4, 0x39, 0xD4, 0x8F, 0x9E, 0xED, 0x34, 0xF2,
    0x26, 0x11, 0x1E, 0x85, 0xCA, 0xEE, 0x5C, 0x74, 0x0C, 0x35, 0x97, 0x4B,
    0xB9, 0x5E, 0x4E, 0x47, 0x09, 0x7F, 0xC1, 0x5C, 0x96, 0xB9, 0xD5, 0x48,
    0x30, 0x3C, 0x6A, 0xD0, 0xB0, 0xB1, 0xE8, 0xAA, 0xE0, 0x83, 0x15, 0xF8,
    0xAB, 0x63, 0x65, 0x94, 0x71, 0xA6, 0x94, 0x84, 0x01, 0x5B, 0x33, 0xD2,
    0x9E, 0x03, 0x36, 0x1C, 0x07, 0x3F, 0x70, 0xE2, 0xD9, 0xAE, 0x3C, 0xE5,
    0x26, 0xF6, 0x21, 0xD6, 0x85, 0xCD, 0xAB, 0xC8, 0xDE, 0xF1, 0x64, 0xEE,
    0x9C, 0x1E, 0xE8, 0x43, 0xFB, 0xAE, 0xA0, 0xCE, 0x6E, 0x91, 0x6F, 0x99,
    0x98, 0xAB, 0xB5, 0x7A, 0x86, 0xE8, 0x4D, 0x79, 0xAA, 0xF2, 0xF5, 0x97,
    0x04, 0x25, 0x49, 0x23, 0xBD, 0x98, 0x3D, 0x52, 0xE8, 0xA2, 0xB5, 0xF0,
    0xCB, 0x7D, 0x11, 0x19, 0x35, 0x33, 0x9D, 0x54, 0xC8, 0x79, 0x3E, 0x5D,
    0xB5, 0x0F, 0xB9, 0x86, 0x7B, 0x39, 0xBF, 0xFD, 0x7B, 0xC7, 0x98, 0x54,
    0xD7, 0x38, 0xEA, 0x38, 0xAD, 0xAB, 0x03, 0xC6, 0x8D, 0xFD, 0x0C, 0xBF};

TestSuite(Key_Genration, .description = "Key generation");

Test(Key_Genration, key_gen)
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    for (int bits = 0; bits <= 4000; bits += 500)
    {
        if (bits < 512)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_rsa_generate_key_pair(&key_pair, bits), != 0, END, 1, "%s --- key_size_bits: %d\n",
                                   "cw_rsa_generate_key_pair should have failed", bits);
        }

        CR_CW_UNIT_TEST_EXPECT(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, 0, "%s --- key_size_bits: %d\n",
                               "cw_rsa_generate_key_pair failed", bits);

    END:
        cw_rsa_delete_key_pair(key_pair);
    }
}

TestSuite(Key_serialization, .description = "Key serialization");

Test(Key_serialization, Read_Write_Public)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_compare = NULL;

    for (int bits = 512; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_serialization_type serialization_type = 0; serialization_type <= CW_RSA_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            RSA_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, "Could not open temp file");

            RSA_UNIT_TEST(cw_rsa_write_public_key_fp(temp_file, key_pair, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_write_public_key_fp");

            rewind(temp_file);

            RSA_UNIT_TEST(cw_rsa_load_public_key_fp(temp_file, &key_pair_compare, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_load_public_key_fp");

            RSA_UNIT_TEST(EVP_PKEY_eq(key_pair, key_pair_compare), != 1, END_SERIALIZATION, "Written and loaded keys are not equal");

        END_SERIALIZATION:
            fclose(temp_file);
            if (key_pair_compare != NULL)
                cw_rsa_delete_key_pair(key_pair_compare);
            key_pair_compare = NULL;
        }
    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_compare = NULL;

    for (int bits = 512; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_serialization_type serialization_type = 0; serialization_type <= CW_RSA_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            RSA_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, "Could not open temp file");

            RSA_UNIT_TEST(cw_rsa_write_private_key_fp(temp_file, key_pair, NULL, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_write_public_key_fp");

            rewind(temp_file);

            RSA_UNIT_TEST(cw_rsa_load_private_key_fp(temp_file, &key_pair_compare, NULL, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_load_public_key_fp");

            RSA_UNIT_TEST(EVP_PKEY_eq(key_pair, key_pair_compare), != 1, END_SERIALIZATION, "Written and loaded keys are not equal");

        END_SERIALIZATION:
            fclose(temp_file);
            if (key_pair_compare != NULL)
                cw_rsa_delete_key_pair(key_pair_compare);
            key_pair_compare = NULL;
        }
    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private_Passphrase)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_compare = NULL;

    const char *passphrase = "Ooc5ooyoh3aibahgh3Ie";

    for (int bits = 512; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_serialization_type serialization_type = 0; serialization_type <= CW_RSA_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            RSA_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, "Could not open temp file");

            if (RSA_IS_DER(serialization_type) == 1)
            {
                RSA_UNIT_TEST_SUPPOSE_FAIL(cw_rsa_write_private_key_fp(temp_file, key_pair, passphrase, serialization_type), != 0,
                                           END_SERIALIZATION, "cw_rsa_write_public_key_fp should have failed");
                goto END_SERIALIZATION;
            }

            RSA_UNIT_TEST(cw_rsa_write_private_key_fp(temp_file, key_pair, passphrase, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_write_public_key_fp");

            rewind(temp_file);

            RSA_UNIT_TEST(cw_rsa_load_private_key_fp(temp_file, &key_pair_compare, passphrase, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_load_public_key_fp");

            RSA_UNIT_TEST(EVP_PKEY_eq(key_pair, key_pair_compare), != 1, END_SERIALIZATION, "Written and loaded keys are not equal");

        END_SERIALIZATION:
            fclose(temp_file);
            if (key_pair_compare != NULL)
                cw_rsa_delete_key_pair(key_pair_compare);
            key_pair_compare = NULL;
        }
    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private_Wrong_Passphrase)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_compare = NULL;

    const char *passphrase = "Ooc5ooyoh3aibahgh3Ie";
    const char *wrong_passphrase = "AhmojohmaiteeNg2uo8W";

    for (int bits = 512; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_serialization_type serialization_type = 0; serialization_type <= CW_RSA_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            RSA_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, "Could not open temp file");

            if (RSA_IS_DER(serialization_type) == 1)
            {
                RSA_UNIT_TEST_SUPPOSE_FAIL(cw_rsa_write_private_key_fp(temp_file, key_pair, passphrase, serialization_type), != 0,
                                           END_SERIALIZATION, "cw_rsa_write_public_key_fp should have failed");
                goto END_SERIALIZATION;
            }

            RSA_UNIT_TEST(cw_rsa_write_private_key_fp(temp_file, key_pair, passphrase, serialization_type), != 1, END_SERIALIZATION, "cw_rsa_write_public_key_fp");

            rewind(temp_file);

            RSA_UNIT_TEST_SUPPOSE_FAIL(cw_rsa_load_private_key_fp(temp_file, &key_pair_compare, wrong_passphrase, serialization_type), != 0,
                                       END_SERIALIZATION, "cw_rsa_load_public_key_fp");

        END_SERIALIZATION:
            fclose(temp_file);
            if (key_pair_compare != NULL)
                cw_rsa_delete_key_pair(key_pair_compare);
            key_pair_compare = NULL;
        }
    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

TestSuite(Signature, .description = "Signature");

cw_rsa_signature_hash rsa_signature_modes[] = {
    CW_RSA_SIG_HASH_SHA_1,
    CW_RSA_SIG_HASH_SHA_224,
    CW_RSA_SIG_HASH_SHA_256,
    CW_RSA_SIG_HASH_SHA_384,
    CW_RSA_SIG_HASH_SHA_512,
    CW_RSA_SIG_HASH_MD5,
    CW_RSA_SIG_HASH_SHA3_224,
    CW_RSA_SIG_HASH_SHA3_256,
    CW_RSA_SIG_HASH_SHA3_384,
    CW_RSA_SIG_HASH_SHA3_512};

Test(Signature, SignAndVerify)
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (int i = 0; i < sizeof(rsa_signature_modes) / sizeof(rsa_signature_modes[0]); i++)
        {
            cw_rsa_signature_hash signature_hash = rsa_signature_modes[i];

            for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
            {
                // if (RSA_IS_OAEP(padding_mode) || (padding_mode == CW_RSA_X931_PADDING && (!(signature_hash == CW_RSA_SIG_HASH_SHA_1 || signature_hash == CW_RSA_SIG_HASH_SHA_256 || signature_hash == CW_RSA_SIG_HASH_SHA_384 || signature_hash == CW_RSA_SIG_HASH_SHA_512))))
                if (RSA_IS_OAEP(padding_mode))
                {
                    CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                           != 0, END_INTERNAL, 1, "%s should have failed --- Padding_mode: %d --- Signature_mode: %s",
                                           "cw_rsa_sign_bytes", padding_mode, cw_fetch_hash_str_internal(signature_hash));

                    goto END_INTERNAL;
                }

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_sign_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_verify_bytes(key_pair, test_vector, sizeof(test_vector), signature, signature_len, signature_hash, padding_mode),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_verify_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Signature, WrongSingature)
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (int i = 0; i < sizeof(rsa_signature_modes) / sizeof(rsa_signature_modes[0]); i++)
        {
            cw_rsa_signature_hash signature_hash = rsa_signature_modes[i];

            for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
            {
                // if (RSA_IS_OAEP(padding_mode) || (padding_mode == CW_RSA_X931_PADDING && (!(signature_hash == CW_RSA_SIG_HASH_SHA_1 || signature_hash == CW_RSA_SIG_HASH_SHA_256 || signature_hash == CW_RSA_SIG_HASH_SHA_384 || signature_hash == CW_RSA_SIG_HASH_SHA_512))))
                if (RSA_IS_OAEP(padding_mode))
                {
                    CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                           != 0, END_INTERNAL, 1, "%s should have failed --- Padding_mode: %d --- Signature_mode: %s",
                                           "cw_rsa_sign_bytes", padding_mode, cw_fetch_hash_str_internal(signature_hash));

                    goto END_INTERNAL;
                }

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_sign_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

                signature[0] += 1;

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_verify_bytes(key_pair, test_vector, sizeof(test_vector), signature, signature_len, signature_hash, padding_mode),
                                       != 0, END_INTERNAL, 1, "%s --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_verify_bytes should have failed", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Signature, WrongKey)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_imposter = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair_imposter, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (int i = 0; i < sizeof(rsa_signature_modes) / sizeof(rsa_signature_modes[0]); i++)
        {
            cw_rsa_signature_hash signature_hash = rsa_signature_modes[i];

            for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
            {
                // if (RSA_IS_OAEP(padding_mode) || (padding_mode == CW_RSA_X931_PADDING && (!(signature_hash == CW_RSA_SIG_HASH_SHA_1 || signature_hash == CW_RSA_SIG_HASH_SHA_256 || signature_hash == CW_RSA_SIG_HASH_SHA_384 || signature_hash == CW_RSA_SIG_HASH_SHA_512))))
                if (RSA_IS_OAEP(padding_mode))
                {
                    CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                           != 0, END_INTERNAL, 1, "%s should have failed --- Padding_mode: %d --- Signature_mode: %s",
                                           "cw_rsa_sign_bytes", padding_mode, cw_fetch_hash_str_internal(signature_hash));

                    goto END_INTERNAL;
                }

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_sign_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

                signature[0] += 1;

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_verify_bytes(key_pair_imposter, test_vector, sizeof(test_vector), signature, signature_len, signature_hash, padding_mode),
                                       != 0, END_INTERNAL, 1, "%s --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_verify_bytes should have failed", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        if (key_pair_imposter != NULL)
            cw_rsa_delete_key_pair(key_pair_imposter);
        continue;
    }
}

Test(Signature, SignAndVerifyNoAlloc)
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (int i = 0; i < sizeof(rsa_signature_modes) / sizeof(rsa_signature_modes[0]); i++)
        {
            cw_rsa_signature_hash signature_hash = rsa_signature_modes[i];

            for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
            {
                signature = calloc(sizeof(uint8_t), 600);

                CR_CW_UNIT_TEST_EXPECT(signature != NULL, != 1, END_INTERNAL, 0,
                                       "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "calloc", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

                // if (RSA_IS_OAEP(padding_mode) || (padding_mode == CW_RSA_X931_PADDING && (!(signature_hash == CW_RSA_SIG_HASH_SHA_1 || signature_hash == CW_RSA_SIG_HASH_SHA_256 || signature_hash == CW_RSA_SIG_HASH_SHA_384 || signature_hash == CW_RSA_SIG_HASH_SHA_512))))
                if (RSA_IS_OAEP(padding_mode))
                {
                    CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, RSA_NO_ALLOC),
                                           != 0, END_INTERNAL, 1, "%s should have failed --- Padding_mode: %d --- Signature_mode: %s",
                                           "cw_rsa_sign_bytes", padding_mode, cw_fetch_hash_str_internal(signature_hash));

                    goto END_INTERNAL;
                }

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_sign_bytes(key_pair, test_vector, sizeof(test_vector), signature_hash, padding_mode, &signature, &signature_len, RSA_NO_ALLOC),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_sign_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

                CR_CW_UNIT_TEST_EXPECT(cw_rsa_verify_bytes(key_pair, test_vector, sizeof(test_vector), signature, signature_len, signature_hash, padding_mode),
                                       != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d --- Signature_mode: %s",
                                       "cw_rsa_verify_bytes", bits, padding_mode, cw_fetch_hash_str_internal(signature_hash));

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

TestSuite(Crypt, .description = "Crypt");

Test(Crypt, EncryptionDecryption)
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len = 0;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;

    uint64_t test_vector_size = 30;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
        {
            if (RSA_IS_PSS(padding_mode) || (padding_mode == CW_RSA_PKCS1_OAEP_SHA512_PADDING && bits == 1024))
            {
                CR_CW_UNIT_TEST_EXPECT(cw_rsa_encrypt_bytes(key_pair, test_vector, test_vector_size, &ciphertext, &ciphertext_len, padding_mode, 0),
                                       != 0, END_INTERNAL, 1, "%s failed --- key_size: %d --- Padding_mode: %d",
                                       "cw_rsa_encrypt_bytes", bits, padding_mode);

                goto END_INTERNAL;
            }

            CR_CW_UNIT_TEST_EXPECT(cw_rsa_encrypt_bytes(key_pair, test_vector, test_vector_size, &ciphertext, &ciphertext_len, padding_mode, 0),
                                   != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d",
                                   "cw_rsa_encrypt_bytes", bits, padding_mode);

            CR_CW_UNIT_TEST_EXPECT(cw_rsa_decrypt_bytes(key_pair, ciphertext, ciphertext_len, &plaintext, &plaintext_len, padding_mode, 0),
                                   != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d",
                                   "cw_rsa_decrypt_bytes", bits, padding_mode);

            CR_CW_UNIT_TEST_EXPECT(plaintext_len == test_vector_size, != 1, END_INTERNAL, 0, "%s --- key_size: %d --- Padding_mode: %d",
                                   "Rsa plaintext len is not equal to ciphertext", bits, padding_mode);

            CR_CW_UNIT_TEST_EXPECT(memcmp(test_vector, plaintext, plaintext_len),
                                   != 0, END_INTERNAL, 0, "%s --- key_size: %d --- Padding_mode: %d",
                                   "memcmp has plaintext and test vector< are not equal", bits, padding_mode);

        END_INTERNAL:
            if (ciphertext != NULL)
                free(ciphertext);
            ciphertext = NULL;

            if (plaintext != NULL)
                free(plaintext);
            plaintext = NULL;
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        continue;
    }
}

Test(Crypt, EncryptionDecryptionWrongPkey)
{
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_imposter = NULL;

    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len = 0;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;

    uint64_t test_vector_size = 30;

    for (int bits = 1024; bits <= 4096; bits += 500)
    {
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair, bits), != 1, END, "cw_rsa_generate_key_pair");
        RSA_UNIT_TEST(cw_rsa_generate_key_pair(&key_pair_imposter, bits), != 1, END, "cw_rsa_generate_key_pair");

        for (cw_rsa_padding_mode padding_mode = CW_RSA_PKCS1_PADDING; padding_mode <= CW_RSA_PKCS1_PSS_PADDING; padding_mode++)
        {
            if (RSA_IS_PSS(padding_mode) || (padding_mode == CW_RSA_PKCS1_OAEP_SHA512_PADDING && bits == 1024))
            {
                CR_CW_UNIT_TEST_EXPECT(cw_rsa_encrypt_bytes(key_pair, test_vector, test_vector_size, &ciphertext, &ciphertext_len, padding_mode, 0),
                                       != 0, END_INTERNAL, 1, "%s failed --- key_size: %d --- Padding_mode: %d",
                                       "cw_rsa_encrypt_bytes", bits, padding_mode);

                goto END_INTERNAL;
            }

            CR_CW_UNIT_TEST_EXPECT(cw_rsa_encrypt_bytes(key_pair, test_vector, test_vector_size, &ciphertext, &ciphertext_len, padding_mode, 0),
                                   != 1, END_INTERNAL, 0, "%s failed --- key_size: %d --- Padding_mode: %d",
                                   "cw_rsa_encrypt_bytes", bits, padding_mode);

            CR_CW_UNIT_TEST_EXPECT(cw_rsa_decrypt_bytes(key_pair_imposter, ciphertext, ciphertext_len, &plaintext, &plaintext_len, padding_mode, 0),
                                   != 0, END_INTERNAL, 1, "%s should have failed --- key_size: %d --- Padding_mode: %d",
                                   "cw_rsa_decrypt_bytes", bits, padding_mode);

        END_INTERNAL:
            if (ciphertext != NULL)
                free(ciphertext);
            ciphertext = NULL;

            if (plaintext != NULL)
                free(plaintext);
            plaintext = NULL;
        }

    END:
        if (key_pair != NULL)
            cw_rsa_delete_key_pair(key_pair);
        if (key_pair_imposter != NULL)
            cw_rsa_delete_key_pair(key_pair_imposter);            
        continue;
    }
}