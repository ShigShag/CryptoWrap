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

#include <internal/ecc_internal.h>

#include <cryptowrap/error.h>

#define EC_UNIT_TEST(func_call, fail_condition, end_point, curve_id, function_str)           \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- curve_id: %s\n", \
                           function_str, cw_fetch_ec_curve_str_internal(curve_id))

#define EC_UNIT_TEST_SUPPOSE_FAIL(func_call, fail_condition, end_point, curve_id, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- curve_id: %s\n",    \
                           function_str, cw_fetch_ec_curve_str_internal(curve_id))

#define EC_UNIT_TEST_VECTOR_SIZE(func_call, fail_condition, end_point, curve_id, vector_size, function_str)      \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- curve_id: %s --- vector_size: %d\n", \
                           function_str, cw_fetch_ec_curve_str_internal(curve_id), vector_size)

#define EC_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(func_call, fail_condition, end_point, curve_id, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- curve_id: %s --- vector_size: %d\n",         \
                           function_str, cw_fetch_ec_curve_str_internal(curve_id), vector_size)

uint8_t test_vector[] = {
    0x78, 0x0B, 0x00, 0x29, 0xC4, 0xF9, 0xAD, 0x4C, 0x87, 0xC3, 0x5C, 0xC4,
    0xD1, 0xD3, 0x9D, 0x6F, 0x95, 0xB8, 0x32, 0x95, 0xD4, 0xD9, 0x70, 0x6A,
    0x87, 0x37, 0xBF, 0x54, 0x74, 0x59, 0x3B, 0x62, 0x6B, 0xC5, 0x42, 0xEC,
    0x1A, 0xED, 0xA1, 0x0A, 0x4E, 0xF9, 0x07, 0x25, 0xD0, 0xFF, 0x9A, 0xC9,
    0x34, 0xB0, 0x36, 0xB6, 0xAF, 0x5E, 0x62, 0xA6, 0x96, 0x93, 0xDA, 0xBB,
    0x25, 0xC0, 0x7B, 0xD8, 0x69, 0xAE, 0x8F, 0xF7, 0x73, 0xB6, 0xEE, 0x8C,
    0xDE, 0x72, 0x2D, 0x7F, 0x44, 0x4E, 0x01, 0x62, 0x4F, 0x22, 0x94, 0xD1,
    0xE9, 0xFC, 0x27, 0x3E, 0x63, 0x41, 0x1D, 0xCA, 0x00, 0xD6, 0xC8, 0x28,
    0x8A, 0x07, 0x74, 0xC3, 0xCC, 0x4D, 0x41, 0x04, 0x0D, 0xFB, 0x1C, 0x6D,
    0x93, 0xBC, 0x6E, 0x6F, 0x0E, 0xEB, 0xC4, 0xAD, 0xFF, 0x91, 0x17, 0x71,
    0xD6, 0x07, 0x1F, 0x2C, 0x13, 0x4A, 0xB2, 0xF1, 0x21, 0xDF, 0x9A, 0x26,
    0x9C, 0x32, 0xDF, 0xBF, 0x57, 0x9B, 0x7D, 0x9B, 0x54, 0xE3, 0xD6, 0x72,
    0x19, 0x2F, 0x2E, 0x90, 0x2D, 0x54, 0x86, 0x7B, 0x13, 0xFC, 0x14, 0x44,
    0x2A, 0xE2, 0x22, 0x21, 0x40, 0xCB, 0x1A, 0x86, 0x81, 0x8C, 0xD1, 0xD4,
    0xA2, 0x78, 0x26, 0x5D, 0x84, 0xF1, 0x53, 0x3F, 0x41, 0x50, 0x57, 0xF9,
    0x82, 0x87, 0x5E, 0xB2, 0x9C, 0x8B, 0x5E, 0xAB, 0x9D, 0x61, 0x5B, 0x51,
    0x3F, 0x77, 0xAB, 0xDD, 0x59, 0xF5, 0xA3, 0xA6, 0x92, 0x60, 0xED, 0x6C,
    0x06, 0x60, 0x15, 0xE8, 0xB5, 0x90, 0x27, 0x98, 0x1A, 0x38, 0x05, 0x46,
    0xBF, 0x23, 0x6E, 0xBE, 0x8B, 0x3F, 0xED, 0x3D, 0x03, 0x61, 0xEB, 0x06,
    0xFC, 0xB6, 0x47, 0xFE, 0x46, 0x24, 0x6E, 0xE2, 0x67, 0xC8, 0xE4, 0x27,
    0xD8, 0xEE, 0xBD, 0xA5, 0x94, 0x20, 0xD6, 0x79, 0xE4, 0x00, 0xA1, 0x10,
    0xF7, 0xB3, 0x12, 0xBB, 0xA6, 0x9E, 0x0A, 0x90, 0x6C, 0xA2, 0x03, 0x5B,
    0x3C, 0x17, 0x3C, 0x84, 0xB8, 0xD4, 0x1A, 0x1A, 0x99, 0x31, 0x54, 0xFB,
    0x09, 0xFA, 0x8B, 0x5E, 0x83, 0x35, 0x17, 0xA6, 0xF0, 0x46, 0x7D, 0xAF,
    0xA7, 0x78, 0x94, 0x60, 0x2F, 0xA7, 0xB7, 0x5F, 0x90, 0x21, 0x01, 0xFA,
    0x6F, 0xC0, 0xE8, 0x89, 0xBD, 0x25, 0x9B, 0xCD, 0xE4, 0x27, 0xDB, 0x45,
    0x62, 0xA7, 0xCA, 0x50, 0xCD, 0x04, 0xEB, 0x56, 0x54, 0xA0, 0xA2, 0x3A,
    0x3D, 0xD3, 0xAD, 0x38, 0x60, 0x75, 0xAF, 0xA2, 0x96, 0xE5, 0xF7, 0xBA,
    0xD8, 0x23, 0x4C, 0x2B, 0x4C, 0xE7, 0xA5, 0x27, 0x73, 0xA7, 0x62, 0x6C,
    0x0A, 0x3A, 0x1F, 0xB4, 0x54, 0xD1, 0x8B, 0xE6, 0xBE, 0xF0, 0xB7, 0x54,
    0xAD, 0xFF, 0x16, 0x35, 0x12, 0x51, 0x77, 0xA1, 0x2F, 0xB1, 0x35, 0x4B,
    0x33, 0x19, 0xEF, 0x35, 0x8A, 0x99, 0xCD, 0x2B, 0x41, 0x5D, 0xE5, 0x02,
    0x4E, 0x62, 0xCB, 0x55, 0x3B, 0x5E, 0x41, 0x87, 0x19, 0x66, 0x78, 0x4C,
    0x77, 0x70, 0x17, 0xF9, 0x99, 0x3F, 0x2D, 0xA0, 0xAC, 0xFE, 0xD6, 0x65,
    0xEA, 0xB3, 0xA1, 0xCC, 0x63, 0xE6, 0x2A, 0x07, 0xC2, 0xC4, 0x01, 0x30,
    0x29, 0x8A, 0x1F, 0x73, 0xF7, 0x18, 0x13, 0x49, 0xE2, 0x03, 0x78, 0x2A,
    0xE6, 0xB2, 0x68, 0x92, 0x79, 0x6A, 0x30, 0x2F, 0x62, 0x1F, 0x42, 0x0D,
    0xD7, 0x90, 0xBA, 0x31, 0x39, 0xA2, 0x4A, 0x24, 0x66, 0x3A, 0xC7, 0x52,
    0xCD, 0x90, 0x88, 0x8C, 0x8C, 0x23, 0x6D, 0x3F, 0x77, 0x66, 0x30, 0x66,
    0xCD, 0x4B, 0x78, 0x9B, 0x02, 0xF3, 0x9F, 0xDB, 0xDA, 0x51, 0xD3, 0x75,
    0xDA, 0xEE, 0x5C, 0xEB, 0x70, 0xD9, 0xF4, 0xC5, 0x45, 0xD0, 0xC5, 0x05,
    0xB5, 0xC6, 0xC2, 0xE7, 0x54, 0x6A, 0x95, 0x93, 0x3C, 0x00, 0x6F, 0xE0,
    0x08, 0x05, 0xD9, 0x2A, 0xC4, 0x2E, 0x52, 0x20, 0x9D, 0x38, 0x48, 0xD8,
    0x32, 0x6B, 0x7F, 0x93, 0x6A, 0x1F, 0x71, 0x66, 0xAB, 0xFF, 0x2E, 0xEF,
    0xCE, 0xDA, 0x79, 0x68, 0x85, 0x65, 0x55, 0x70, 0x05, 0x0D, 0x17, 0x3E,
    0x7E, 0x79, 0xEC, 0x34, 0x6E, 0x1C, 0xDB, 0x07, 0x42, 0x42, 0x25, 0xA6,
    0x91, 0x94, 0xAF, 0x14, 0xF8, 0x23, 0x14, 0x27, 0xDA, 0x63, 0xC9, 0x15,
    0xDD, 0x59, 0x3B, 0x3D, 0xD6, 0xD0, 0x21, 0x0A, 0x23, 0xE1, 0x7D, 0xA2,
    0x0D, 0xBA, 0x71, 0x83, 0x68, 0x01, 0xD5, 0x51, 0xE8, 0x3B, 0x17, 0xC8,
    0xB7, 0xBA, 0x9C, 0x0A, 0xE3, 0xF5, 0xDD, 0xED, 0xAB, 0x43, 0x56, 0x98,
    0xDF, 0x17, 0x4F, 0xC7, 0xAA, 0xD9, 0xA4, 0xEB, 0x28, 0xDE, 0x96, 0x19,
    0xC2, 0x2D, 0x13, 0x7F, 0xAC, 0xE6, 0x00, 0xC3, 0x28, 0x5A, 0x13, 0x4C,
    0xEE, 0x6A, 0x53, 0x0E, 0x70, 0xA7, 0x4B, 0x90, 0x4C, 0x76, 0xFD, 0x8B,
    0x09, 0xD5, 0x19, 0xEF, 0x8A, 0xAB, 0xE0, 0x39, 0xDB, 0xCD, 0x42, 0x3E,
    0x81, 0xC5, 0xD5, 0x7E, 0xBD, 0x78, 0x31, 0x25, 0x31, 0x18, 0x58, 0x6E,
    0xBB, 0xCC, 0x88, 0x81, 0x6F, 0x37, 0xD4, 0x9A, 0x0A, 0xEE, 0xE1, 0x38,
    0xB3, 0x9A, 0x5B, 0x92, 0x7A, 0x85, 0x2F, 0xFB, 0x3A, 0xEE, 0xEB, 0xDC,
    0x6C, 0x16, 0x4F, 0x3E, 0x70, 0xCC, 0xBD, 0xE4, 0x9C, 0x2E, 0xB7, 0xCD,
    0x41, 0xDE, 0xD5, 0x89, 0x87, 0x90, 0x14, 0xFC, 0x47, 0xAE, 0x56, 0xF6,
    0x61, 0x6F, 0x5B, 0xE9, 0x42, 0x56, 0xD7, 0x75, 0x6C, 0x1D, 0xB2, 0xE5,
    0x8B, 0xAB, 0x34, 0x75, 0xD0, 0xA1, 0x7C, 0x69, 0x97, 0xF3, 0xCD, 0x6B,
    0x55, 0xC9, 0x6A, 0x41, 0x11, 0x09, 0xA5, 0xD1, 0xA9, 0x17, 0xA0, 0xD6,
    0x7E, 0xBB, 0xF0, 0x59, 0xB9, 0x27, 0x14, 0x8E, 0x15, 0x7E, 0xF2, 0x54,
    0x4F, 0x02, 0x39, 0x14, 0x0B, 0x3B, 0x5B, 0xFE, 0x39, 0xC9, 0xCF, 0x91,
    0x80, 0x36, 0xDE, 0xE4, 0xF7, 0x70, 0xEA, 0x5F, 0x99, 0x7F, 0x56, 0x9D,
    0x3D, 0x60, 0x9D, 0x90, 0x9F, 0xED, 0xF6, 0xDF, 0x71, 0xE5, 0xC2, 0xA8,
    0x66, 0x92, 0xD5, 0xB2, 0xCE, 0x37, 0x34, 0xF2, 0x34, 0x26, 0x0A, 0x68,
    0xE9, 0x28, 0xD0, 0x44, 0x67, 0x71, 0xA5, 0x8C, 0xED, 0xDD, 0xA8, 0xC7,
    0x64, 0xAC, 0xC4, 0x6E, 0x09, 0x2C, 0x0F, 0x05, 0x30, 0x34, 0x26, 0x14,
    0xF5, 0x16, 0x33, 0x93, 0xB2, 0xAC, 0xF8, 0x0D, 0xB9, 0x83, 0x88, 0xEC,
    0xBC, 0x1F, 0xD7, 0xCF, 0x40, 0x55, 0x8A, 0xE4, 0xA6, 0xDA, 0x59, 0xDC,
    0x36, 0x8D, 0xD2, 0x57, 0x1C, 0x04, 0x50, 0x5A, 0x62, 0xB7, 0x42, 0x60,
    0x6D, 0xF1, 0xB2, 0x4F, 0x7E, 0x14, 0x05, 0xC4, 0xCF, 0xFE, 0x9C, 0xE7,
    0xB8, 0x5D, 0x18, 0xEF, 0xBA, 0x22, 0xBE, 0x3B, 0xC3, 0x08, 0xB5, 0xEE,
    0x02, 0xBC, 0x73, 0x3E, 0xA8, 0xF0, 0x73, 0xE7, 0xA9, 0xAE, 0xD7, 0xC0,
    0x9B, 0x95, 0x7F, 0xF8, 0xE5, 0x46, 0x65, 0x8F, 0x0F, 0x80, 0x60, 0x3A,
    0x48, 0x93, 0xC2, 0x0C, 0x52, 0x82, 0xE0, 0x09, 0x09, 0xBA, 0xC7, 0x01,
    0xD0, 0x9C, 0x8E, 0xE9, 0xA6, 0x5F, 0x16, 0xD3, 0x77, 0x2F, 0xFA, 0xE7,
    0x88, 0x26, 0xB9, 0xC9, 0xF6, 0x8F, 0x02, 0xAC, 0x98, 0x0D, 0x48, 0x81,
    0xA9, 0x1A, 0xE8, 0x88, 0x09, 0x0B, 0xE9, 0x58, 0x7A, 0x21, 0x57, 0xE9,
    0x00, 0x92, 0x02, 0x35, 0x73, 0xA5, 0xC3, 0x51, 0x2B, 0x51, 0x6E, 0xA9,
    0xDA, 0x84, 0xA9, 0x24, 0xFA, 0x6E, 0x54, 0xBC, 0x95, 0xD3, 0x01, 0xA3,
    0xBA, 0x0A, 0xD7, 0x50, 0x58, 0xDB, 0xF0, 0xBF, 0x84, 0xC7, 0xBF, 0x22,
    0x06, 0x5A, 0x93, 0x68, 0x03, 0xD8, 0x21, 0x27, 0x00, 0x3D, 0xF8, 0x6E,
    0x6F, 0xAA, 0x7B, 0x4A, 0x5E, 0x91, 0x62, 0x66, 0x27, 0x51, 0x61, 0x35,
    0xEE, 0x14, 0x1A, 0x44, 0xCB, 0x3F, 0x20, 0x24, 0x6E, 0x2A, 0x8D, 0x8B,
    0xD5, 0xEF, 0x98, 0xAA, 0xBC, 0x3E, 0xEA, 0xE7, 0x56, 0x0B, 0x28, 0xDB,
    0x40, 0x78, 0xF6, 0x6E, 0xAB, 0x22, 0xAE, 0xBB, 0x6D, 0x3D, 0x1B, 0x99,
    0x7B, 0xC0, 0xF6, 0x38, 0x03, 0x72, 0x72, 0x34, 0x09, 0xC7, 0xB2, 0x57,
    0xB7, 0x63, 0xE2, 0xAB, 0x39, 0x7C, 0xA1, 0x38, 0x0A, 0x8D, 0xE7, 0x9A,
    0xDD, 0x83, 0x41, 0x7D, 0x04, 0x08, 0x47, 0x8B, 0x97, 0x17, 0xA6, 0xB3,
    0xB3, 0x34, 0x2D, 0xA2, 0xAF, 0xE8, 0xC2, 0x26, 0xF0, 0x6D, 0x54, 0x8F,
    0x58, 0xB7, 0x08, 0x80, 0x6E, 0xD3, 0x32, 0x57, 0xF9, 0xCE, 0x46, 0x8E,
    0x83, 0xCE, 0x26, 0x64, 0x52, 0x1C, 0xC8, 0x23, 0x33, 0x55, 0xB7, 0x2E,
    0xAE, 0xED, 0x7D, 0x6C, 0xFD, 0xE8, 0xE6, 0x42, 0xE8, 0xC9, 0xA9, 0x3D,
    0xF0, 0x38, 0x8F, 0x9E, 0xCC, 0xB3, 0x15, 0xCE, 0x18, 0xC8, 0xB3, 0xDC,
    0x4C, 0xCB, 0xDA, 0x65, 0x99, 0x56, 0x6E, 0xAA, 0x77, 0x01, 0x11, 0xBC,
    0x62, 0x7B, 0x75, 0x9E, 0xDC, 0x0D, 0xD0, 0x24, 0xA6, 0x5A, 0xD3, 0x06,
    0x52, 0xAB, 0xA1, 0x15, 0xA3, 0x79, 0x0A, 0x10, 0x2A, 0x58, 0xA7, 0x2F,
    0xA1, 0xB9, 0x72, 0x05, 0xA2, 0xBC, 0x05, 0x12, 0x84, 0x36, 0xEE, 0x93,
    0x76, 0xB6, 0x04, 0xD3, 0x1F, 0x69, 0xE2, 0x0C, 0xFF, 0x2E, 0x1A, 0x7C,
    0x23, 0x88, 0xA1, 0xA3, 0xD4, 0x23, 0xAD, 0xBB, 0x0E, 0xFB, 0xAC, 0x41,
    0xAB, 0x71, 0xD1, 0x65, 0xD7, 0x8E, 0x69, 0xFE, 0x6C, 0x2F, 0xDC, 0xDE,
    0x06, 0x1A, 0xC2, 0x3D, 0x97, 0x3D, 0xBB, 0x20, 0x23, 0x77, 0x56, 0x88,
    0xE3, 0x5B, 0x06, 0x18, 0x50, 0xC8, 0x05, 0xC6, 0xF1, 0x80, 0xF8, 0xB9,
    0x56, 0xED, 0x25, 0x95, 0xDB, 0xD6, 0x43, 0x6A, 0x54, 0x90, 0xB4, 0xE1,
    0x37, 0x04, 0x58, 0xCE, 0xA9, 0x59, 0xD9, 0x1B, 0xE4, 0xEF, 0x0C, 0x04,
    0xE3, 0xA0, 0x29, 0xF4, 0x63, 0x3A, 0xA2, 0x08, 0x6E, 0x35, 0x3C, 0x08,
    0x15, 0x23, 0x43, 0x65, 0xDF, 0x1F, 0x58, 0x78, 0x9B, 0x96, 0xAC, 0x39,
    0x39, 0x44, 0x38, 0xFD, 0x52, 0x31, 0x6F, 0xDB, 0x64, 0x42, 0xF3, 0x38,
    0x05, 0xF3, 0xA8, 0xF2, 0x5A, 0x4C, 0x47, 0x37, 0x77, 0xAB, 0x55, 0x1B,
    0x3A, 0x77, 0x85, 0x63, 0x4F, 0x90, 0x2F, 0x02, 0x4F, 0xA1, 0x29, 0xA4,
    0xFB, 0x48, 0xAA, 0x43, 0x27, 0x31, 0xF1, 0xF3, 0x59, 0x1F, 0x84, 0xAE,
    0xF9, 0x4B, 0xFE, 0xC2, 0x56, 0x34, 0x0E, 0x54, 0x18, 0x61, 0xA7, 0x56,
    0xCE, 0x3B, 0xDD, 0xDF, 0xA9, 0x6A, 0x62, 0xA1, 0xC8, 0xA6, 0xF8, 0x49,
    0xBC, 0x35, 0x23, 0xC0, 0x52, 0x69, 0x52, 0xDD, 0x32, 0xB8, 0x53, 0x72,
    0x05, 0xD1, 0xF5, 0x78, 0x2A, 0x55, 0x96, 0xBD, 0xDA, 0xCB, 0x80, 0xD8,
    0x2D, 0x05, 0x94, 0x23, 0x6E, 0x13, 0xC8, 0x1E, 0xB1, 0xA0, 0x55, 0x0B,
    0x3C, 0xB5, 0xF0, 0x95, 0xEF, 0x25, 0x80, 0xB0, 0xBF, 0xA7, 0x71, 0xDD,
    0x2D, 0xBF, 0x62, 0x71, 0xF5, 0x5B, 0x3F, 0xBF, 0x1D, 0x02, 0x35, 0x4F};

TestSuite(Key_Generation, .description = "Key generation");

Test(Key_Generation, key_gen)
{
    ECC_KEY_PAIR pkey = NULL;

    for (cw_elliptic_curve_type curve_id; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        pkey = NULL;
    }
}

TestSuite(Key_serialization, .description = "Key serialization");

Test(Key_serialization, Read_Write_Public)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_compare = NULL;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (cw_ecc_serialization_type serialization_type = 0; serialization_type <= CW_ECC_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            EC_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, curve_id, "Could not open temp file");

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_public_key_fp(temp_file, pkey, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            rewind(temp_file);

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_load_public_key_fp(temp_file, &pkey_compare, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_load_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            CR_CW_UNIT_TEST_EXPECT(EVP_PKEY_eq(pkey, pkey_compare),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "Written and loaded key are not equal",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

        END_SERIALIZATION:
            fclose(temp_file);
            if (pkey_compare != NULL)
                cw_ecc_delete_key_pair(pkey_compare);
            pkey_compare = NULL;
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_compare = NULL;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (cw_ecc_serialization_type serialization_type = 0; serialization_type <= CW_ECC_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            EC_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, curve_id, "Could not open temp file");

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, NULL, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            rewind(temp_file);

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_load_private_key_fp(temp_file, &pkey_compare, NULL, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_load_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            CR_CW_UNIT_TEST_EXPECT(EVP_PKEY_eq(pkey, pkey_compare),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "Written and loaded keys are not equal",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

        END_SERIALIZATION:
            fclose(temp_file);
            if (pkey_compare != NULL)
                cw_ecc_delete_key_pair(pkey_compare);
            pkey_compare = NULL;
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Key_serialization, Read_Write_Wrong_Serialization_Type)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_compare = NULL;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (cw_ecc_serialization_type serialization_type = 0; serialization_type <= CW_ECC_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            EC_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, curve_id, "Could not open temp file");

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, NULL, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            rewind(temp_file);

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_load_private_key_fp(temp_file, &pkey_compare, NULL, (EC_IS_PEM(serialization_type) ? CW_ECC_DER : CW_ECC_PEM)),
                                   != 0, END_SERIALIZATION, 1, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_load_public_key should have failed",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

        END_SERIALIZATION:
            fclose(temp_file);
            if (pkey_compare != NULL)
                cw_ecc_delete_key_pair(pkey_compare);
            pkey_compare = NULL;
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private_Passphrase)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_compare = NULL;

    const char *passphrase = "fah6noh6ahnainegheizaiNuucaePe";

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (cw_ecc_serialization_type serialization_type = 0; serialization_type <= CW_ECC_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            EC_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, curve_id, "Could not open temp file");

            if (EC_IS_DER(serialization_type) == 1)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, passphrase, serialization_type),
                                       != 0, END_SERIALIZATION, 1, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key should have failed",
                                       cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));
                goto END_SERIALIZATION;
            }

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, passphrase, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            rewind(temp_file);

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_load_private_key_fp(temp_file, &pkey_compare, passphrase, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_load_public_key",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            CR_CW_UNIT_TEST_EXPECT(EVP_PKEY_eq(pkey, pkey_compare),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "Written and loaded key are not equal",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

        END_SERIALIZATION:
            fclose(temp_file);
            if (pkey_compare != NULL)
                cw_ecc_delete_key_pair(pkey_compare);
            pkey_compare = NULL;
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Key_serialization, Read_Write_Private_Wrong_Passphrase)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_compare = NULL;

    const char *passphrase = "ieng5eefeu2eTei9ahNg6ofah8ieze";
    const char *wrong_passphrase = "vo7phae2zaeSaiN2rashiuwikahCai";

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (cw_ecc_serialization_type serialization_type = 0; serialization_type <= CW_ECC_PEM; serialization_type++)
        {
            FILE *temp_file = get_temp_file();
            EC_UNIT_TEST((temp_file != NULL), != 1, END_SERIALIZATION, curve_id, "Could not open temp file");

            if (EC_IS_DER(serialization_type) == 1)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, passphrase, serialization_type),
                                       != 0, END_SERIALIZATION, 1, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key should have failed",
                                       cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));
                goto END_SERIALIZATION;
            }

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_write_private_key_fp(temp_file, pkey, passphrase, serialization_type),
                                   != 1, END_SERIALIZATION, 0, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_write_public_key should have failed",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

            rewind(temp_file);

            CR_CW_UNIT_TEST_EXPECT(cw_ecc_load_private_key_fp(temp_file, &pkey_compare, wrong_passphrase, serialization_type),
                                   != 0, END_SERIALIZATION, 1, "%s --- curve_id: %s--- serialization_type: %s", "cw_ecc_load_public_key should have failed",
                                   cw_fetch_ec_curve_str_internal(curve_id), cw_fetch_ec_serialization_type_str_internal(serialization_type));

        END_SERIALIZATION:
            fclose(temp_file);
            if (pkey_compare != NULL)
                cw_ecc_delete_key_pair(pkey_compare);
            pkey_compare = NULL;
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

TestSuite(Signature, .description = "Signature");

cw_ecc_signature_hash signature_hash_array[] = {CW_ECC_SIG_HASH_SHA1,
                                                      CW_ECC_SIG_HASH_SHA224,
                                                      CW_ECC_SIG_HASH_SHA256,
                                                      CW_ECC_SIG_HASH_SHA384,
                                                      CW_ECC_SIG_HASH_MD5,
                                                      CW_ECC_SIG_HASH_SHA512,
                                                      CW_ECC_SIG_HASH_SHA3_224,
                                                      CW_ECC_SIG_HASH_SHA3_256,
                                                      CW_ECC_SIG_HASH_SHA3_384,
                                                      CW_ECC_SIG_HASH_SHA3_512};

Test(Signature, SignAndVerify)
{
    ECC_KEY_PAIR pkey = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (uint64_t test_vector_size = 1; test_vector_size < sizeof(test_vector); test_vector_size += sizeof(test_vector) / 5)
        {
            for (int i = 0; i < sizeof(signature_hash_array) / sizeof(signature_hash_array[0]); i++)
            {
                cw_ecc_signature_hash signature_algorithm = signature_hash_array[i];

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_sign_bytes(pkey, test_vector, test_vector_size, signature_algorithm, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_sign_bytes",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_verify_bytes(pkey, test_vector, test_vector_size, signature, signature_len, signature_algorithm),
                                       != 1, END_INTERNAL, 0, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_verify_bytes",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Signature, WrongSignature)
{
    ECC_KEY_PAIR pkey = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (uint64_t test_vector_size = 1; test_vector_size < sizeof(test_vector); test_vector_size += sizeof(test_vector) / 5)
        {
            for (int i = 0; i < sizeof(signature_hash_array) / sizeof(signature_hash_array[0]); i++)
            {
                cw_ecc_signature_hash signature_algorithm = signature_hash_array[i];

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_sign_bytes(pkey, test_vector, test_vector_size, signature_algorithm, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_sign_bytes",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

                signature[0] += 1;

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_verify_bytes(pkey, test_vector, test_vector_size, signature, signature_len, signature_algorithm),
                                       != 0, END_INTERNAL, 1, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_verify_bytes should have failed",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}

Test(Signature, WrongPkey)
{
    ECC_KEY_PAIR pkey = NULL;
    ECC_KEY_PAIR pkey_imposter = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey_imposter, curve_id), != 1, END, (curve_id + 1) % CW_BRAINPOOLP512T1, "cw_ecc_generate_key_pair");

        for (uint64_t test_vector_size = 1; test_vector_size < sizeof(test_vector); test_vector_size += sizeof(test_vector) / 5)
        {
            for (int i = 0; i < sizeof(signature_hash_array) / sizeof(signature_hash_array[0]); i++)
            {
                cw_ecc_signature_hash signature_algorithm = signature_hash_array[i];

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_sign_bytes(pkey, test_vector, test_vector_size, signature_algorithm, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_sign_bytes",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_verify_bytes(pkey_imposter, test_vector, test_vector_size, signature, signature_len, signature_algorithm),
                                       != 0, END_INTERNAL, 1, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_verify_bytes should have failed",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        if (pkey_imposter != NULL)
            cw_ecc_delete_key_pair(pkey_imposter);
        continue;
    }
}

Test(Signature, WrongTestVectorSize)
{
    ECC_KEY_PAIR pkey = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    for (cw_elliptic_curve_type curve_id = 0; curve_id <= CW_BRAINPOOLP512T1; curve_id++)
    {
        EC_UNIT_TEST(cw_ecc_generate_key_pair(&pkey, curve_id), != 1, END, curve_id, "cw_ecc_generate_key_pair");

        for (uint64_t test_vector_size = 1; test_vector_size < sizeof(test_vector); test_vector_size += sizeof(test_vector) / 5)
        {
            for (int i = 0; i < sizeof(signature_hash_array) / sizeof(signature_hash_array[0]); i++)
            {
                cw_ecc_signature_hash signature_algorithm = signature_hash_array[i];

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_sign_bytes(pkey, test_vector, test_vector_size, signature_algorithm, &signature, &signature_len, 0),
                                       != 1, END_INTERNAL, 0, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_sign_bytes",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

                CR_CW_UNIT_TEST_EXPECT(cw_ecc_verify_bytes(pkey, test_vector, test_vector_size + 1, signature, signature_len, signature_algorithm),
                                       != 0, END_INTERNAL, 1, "%s --- curve_id: %s--- padding_type: %d", "cw_ecc_verify_bytes should have failed",
                                       cw_fetch_ec_curve_str_internal(curve_id), signature_algorithm);

            END_INTERNAL:
                if (signature != NULL)
                    free(signature);
                signature = NULL;
            }
        }
    END:
        if (pkey != NULL)
            cw_ecc_delete_key_pair(pkey);
        continue;
    }
}
