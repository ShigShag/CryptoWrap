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

#include <cryptowrap/mac.h>
#include <internal/fetching.h>
#include <internal/unit_test/cw_uint_test_internal.h>

#define MAC_UNIT_TEST(func_call, fail_condition, end_point, function_str)   \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s\n", \
                           function_str)

#define MAC_UNIT_TEST_SUPPOSE_FAIL(func_call, fail_condition, end_point, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s\n",            \
                           function_str)

#define MAC_UNIT_TEST_VECTOR_SIZE(func_call, fail_condition, end_point, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- vector_size: %d\n",    \
                           function_str, vector_size)

#define MAC_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(func_call, fail_condition, end_point, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- vector_size: %d\n",                 \
                           function_str, vector_size)

uint8_t input_vector[1024] = {
    0x26, 0x78, 0xFE, 0x00, 0xE5, 0x6E, 0xEF, 0x40, 0x49, 0x3D, 0xA2, 0x09,
    0x7F, 0x58, 0x61, 0x0D, 0x08, 0x4B, 0x4B, 0xEA, 0x87, 0x0A, 0x01, 0xB3,
    0x21, 0x55, 0x0A, 0x09, 0xED, 0x2C, 0x6F, 0xA7, 0x79, 0x3D, 0x79, 0x8A,
    0x04, 0x37, 0xD5, 0x14, 0xC7, 0x2F, 0x39, 0x48, 0x26, 0x77, 0xC9, 0x6E,
    0xEB, 0x34, 0x31, 0x5D, 0xB4, 0x0C, 0x28, 0xAE, 0xFF, 0x5E, 0xDA, 0xFC,
    0xC7, 0xA6, 0x26, 0x15, 0xD7, 0x55, 0x21, 0x71, 0xF5, 0xB2, 0x2B, 0x64,
    0xB8, 0x0C, 0xC6, 0x47, 0xD5, 0x90, 0xAE, 0x13, 0xA0, 0x08, 0x38, 0x8A,
    0xEB, 0xEF, 0xD0, 0xC9, 0x99, 0x45, 0x59, 0x31, 0xA6, 0xB2, 0xD2, 0xCB,
    0x93, 0x83, 0x2F, 0x9B, 0x39, 0x85, 0x4A, 0x9C, 0x70, 0xB5, 0x65, 0xA5,
    0x72, 0x2D, 0x9B, 0xA5, 0x49, 0x55, 0x25, 0x86, 0x14, 0x88, 0xA3, 0x9D,
    0x75, 0x66, 0x07, 0xA2, 0x80, 0x1A, 0xB6, 0x2A, 0xAF, 0x71, 0xF1, 0x1D,
    0x29, 0xAC, 0x38, 0xD9, 0xAC, 0x9C, 0x98, 0xE9, 0xA8, 0x47, 0x99, 0xA4,
    0xDC, 0xAE, 0xC6, 0x2F, 0x6E, 0x64, 0xBA, 0x85, 0x8B, 0x92, 0x66, 0x1F,
    0xD2, 0x60, 0x0D, 0xF9, 0x8F, 0xF8, 0xF5, 0x3D, 0x83, 0x04, 0xA4, 0xF9,
    0x94, 0x98, 0x4F, 0x2B, 0x58, 0x82, 0x3B, 0x60, 0x89, 0x2C, 0x9B, 0x15,
    0x8D, 0xED, 0x63, 0x52, 0x88, 0x75, 0x11, 0xF1, 0x39, 0x97, 0x10, 0xC3,
    0x34, 0x38, 0xFE, 0x49, 0x6F, 0x19, 0x41, 0x91, 0x07, 0x0C, 0xB9, 0x24,
    0x9E, 0x02, 0x7E, 0x8A, 0x1E, 0x60, 0x60, 0x1C, 0xAB, 0x3C, 0x42, 0x19,
    0xBF, 0x83, 0x62, 0x72, 0xEA, 0x77, 0x17, 0x1C, 0x98, 0x21, 0x47, 0x85,
    0x8C, 0xEF, 0x18, 0x5A, 0xAE, 0x3A, 0x7B, 0x9E, 0x49, 0x29, 0x4E, 0x4D,
    0x46, 0xC3, 0xB1, 0xE5, 0xF0, 0x80, 0x62, 0xED, 0xC1, 0xD6, 0xD7, 0xAC,
    0x1E, 0xB9, 0x27, 0xC4, 0x99, 0x11, 0x98, 0x73, 0x3E, 0x66, 0xAE, 0xED,
    0x41, 0x1C, 0x97, 0x41, 0xD7, 0x05, 0xCA, 0xB8, 0x0D, 0x9F, 0x41, 0x85,
    0x9E, 0x47, 0x3F, 0x05, 0x5D, 0x39, 0xD9, 0x08, 0x9E, 0xD0, 0x03, 0x3B,
    0x4E, 0x3D, 0x99, 0xBD, 0xA9, 0xDD, 0x42, 0x49, 0xFD, 0x38, 0x03, 0xD0,
    0x66, 0x0C, 0xCE, 0x49, 0x40, 0x1C, 0xB5, 0x5E, 0x3E, 0x4B, 0x13, 0x90,
    0xC2, 0x6C, 0x0E, 0x47, 0x79, 0x8E, 0xB8, 0x47, 0x25, 0xC9, 0x0B, 0xDE,
    0xDF, 0xD2, 0x29, 0x32, 0x70, 0xCA, 0x0B, 0xDC, 0xD6, 0xB7, 0x75, 0x2A,
    0x18, 0xE1, 0x86, 0x52, 0x0F, 0x05, 0x8C, 0x5C, 0x51, 0x73, 0x60, 0x3B,
    0xE7, 0x42, 0xCB, 0x67, 0xC1, 0x6B, 0xF7, 0x6D, 0xB0, 0x2E, 0x0E, 0xBC,
    0xDA, 0xCD, 0xA6, 0xA1, 0x7E, 0x01, 0xA8, 0x27, 0xBD, 0xE5, 0xE5, 0x7E,
    0xB4, 0xFA, 0x8D, 0xCD, 0xAD, 0xF4, 0x94, 0x3B, 0xFA, 0xA7, 0x0A, 0x5D,
    0x8C, 0x43, 0xE1, 0x1E, 0x2C, 0x46, 0x8B, 0x57, 0xB5, 0x9E, 0xB0, 0xE0,
    0x3F, 0x9D, 0xE7, 0xC2, 0x66, 0x0A, 0xA7, 0x02, 0xEE, 0xB4, 0xCC, 0xBA,
    0xC2, 0xDD, 0x43, 0x7F, 0x1B, 0xB7, 0x8D, 0x5C, 0xD2, 0x20, 0xAD, 0x12,
    0x16, 0xDB, 0xFD, 0xD2, 0x94, 0xEB, 0x71, 0x5A, 0x75, 0x75, 0x2C, 0xD3,
    0x18, 0x29, 0xCC, 0x44, 0xB0, 0x9D, 0xFC, 0x0F, 0xD2, 0x30, 0x66, 0x42,
    0xB4, 0xC7, 0x32, 0x92, 0xE5, 0x9E, 0x91, 0xAD, 0x19, 0x33, 0x83, 0xA1,
    0xED, 0x61, 0xE7, 0xF0, 0x06, 0x3C, 0x14, 0x7D, 0x8D, 0xBD, 0x9B, 0x0C,
    0x1E, 0x3C, 0x87, 0x22, 0xE1, 0xB8, 0xCF, 0xD2, 0xD4, 0xF7, 0x07, 0xFC,
    0xDE, 0xFF, 0xE3, 0xA8, 0x60, 0x50, 0x73, 0xA9, 0xB0, 0x21, 0x38, 0x0F,
    0x00, 0xCC, 0x84, 0x6B, 0x45, 0xC0, 0xBA, 0xB0, 0x51, 0xD8, 0x05, 0xBD,
    0xEA, 0x1F, 0xCB, 0x1D, 0xC6, 0x8F, 0xFB, 0xEE, 0x43, 0x98, 0x36, 0x69,
    0x2E, 0xE1, 0x2C, 0x57, 0x64, 0xB8, 0x54, 0x1A, 0xFB, 0x72, 0x95, 0x6F,
    0xDE, 0x1C, 0xFD, 0x37, 0x16, 0xAD, 0x62, 0x6A, 0x18, 0xAB, 0x9B, 0xDC,
    0x7E, 0x2A, 0x32, 0x07, 0xC9, 0x2B, 0x6B, 0xC1, 0x05, 0x42, 0x3E, 0x62,
    0x14, 0xFA, 0x56, 0xAC, 0x69, 0x96, 0x23, 0xB0, 0xE2, 0x2A, 0x2E, 0xFB,
    0x63, 0x33, 0x2F, 0xFB, 0x58, 0xDB, 0xF2, 0xFA, 0x4E, 0xA6, 0x7B, 0x5C,
    0x63, 0x45, 0x70, 0xC1, 0x98, 0x27, 0x12, 0x48, 0xF6, 0xD9, 0x7E, 0x47,
    0x1E, 0x80, 0x48, 0x96, 0x06, 0xC6, 0x74, 0xDF, 0x7C, 0x2F, 0xAD, 0xB6,
    0xB5, 0xF6, 0xE6, 0xB8, 0xBB, 0x00, 0xD0, 0x8E, 0xCE, 0xC3, 0xDB, 0xE7,
    0x63, 0x5B, 0x26, 0x01, 0xBF, 0xBC, 0xEF, 0x8A, 0x16, 0xAA, 0x1C, 0xCE,
    0x19, 0x51, 0x80, 0x40, 0x95, 0x80, 0x5E, 0x72, 0xE7, 0x32, 0x90, 0x71,
    0x64, 0x5F, 0xBF, 0x02, 0x90, 0xC8, 0x86, 0x73, 0x7D, 0xA9, 0x93, 0x3C,
    0x06, 0x45, 0x29, 0x65, 0x17, 0xD7, 0x28, 0x7D, 0xDE, 0x84, 0x19, 0xA4,
    0xB4, 0xD3, 0x7E, 0xAF, 0xC4, 0xF3, 0xF6, 0x9C, 0x6B, 0x1A, 0xD8, 0x51,
    0x88, 0x7A, 0x85, 0x94, 0x1F, 0x3D, 0xFC, 0x33, 0xA2, 0xD5, 0xCA, 0xCA,
    0xD6, 0xFA, 0x3B, 0x67, 0xDA, 0x2A, 0xAD, 0xCF, 0x57, 0x08, 0x35, 0x60,
    0x92, 0x12, 0x5E, 0xA8, 0x28, 0xB2, 0x80, 0xE7, 0x3D, 0x4A, 0xC4, 0x7B,
    0x3F, 0x64, 0x22, 0x65, 0x86, 0x68, 0xF3, 0xE8, 0xD8, 0x28, 0x25, 0x20,
    0x1B, 0x41, 0x93, 0x7D, 0xF3, 0x50, 0xC7, 0xF5, 0xFB, 0xAB, 0x7E, 0x69,
    0x17, 0xCB, 0x62, 0x34, 0x9A, 0x39, 0x8A, 0x76, 0x13, 0xDE, 0xE2, 0xD1,
    0xD4, 0x80, 0xC4, 0xC5, 0x44, 0x08, 0xEE, 0xE1, 0xA3, 0xD1, 0xE7, 0xD6,
    0xB5, 0x34, 0x70, 0x92, 0x57, 0x72, 0xD1, 0x4C, 0x3B, 0xE2, 0x09, 0xE2,
    0x1C, 0x58, 0x5F, 0xBA, 0x23, 0xA2, 0x7A, 0x6B, 0x26, 0xC1, 0xEF, 0x5B,
    0xA9, 0xB9, 0x23, 0xCD, 0xA5, 0x49, 0xBA, 0x91, 0x99, 0xAA, 0x86, 0x09,
    0x67, 0x89, 0x50, 0x96, 0x03, 0x41, 0x56, 0x59, 0xF2, 0x33, 0x39, 0x51,
    0x8B, 0x58, 0x33, 0x78, 0x56, 0x65, 0x94, 0x65, 0x17, 0x50, 0x0E, 0x50,
    0x0C, 0x6D, 0xAB, 0xB7, 0x1C, 0x75, 0xB2, 0xDC, 0xEE, 0xA2, 0x59, 0x3A,
    0x2A, 0xF2, 0xF3, 0x4F, 0xC6, 0x3A, 0x89, 0xFD, 0x05, 0x89, 0x6E, 0x13,
    0xDC, 0x28, 0xB5, 0x71, 0x8A, 0x0B, 0x50, 0x07, 0x46, 0x95, 0x57, 0x2E,
    0x7F, 0x5A, 0x7A, 0x35, 0x54, 0x13, 0x2C, 0x45, 0x2D, 0x1C, 0xA2, 0x7E,
    0x41, 0x3A, 0xF2, 0xEF, 0x7F, 0x87, 0x18, 0x85, 0xE6, 0x4E, 0xEA, 0xD2,
    0x23, 0x34, 0x3E, 0x2B, 0xF0, 0x04, 0xA1, 0xA0, 0xE9, 0x06, 0xD9, 0xBF,
    0xEA, 0xC6, 0x80, 0xE3, 0x1E, 0x95, 0x5D, 0xDC, 0xD6, 0xD7, 0x79, 0x06,
    0xC9, 0x7A, 0x0A, 0x10, 0x85, 0xAF, 0xF5, 0xAB, 0xA8, 0x6A, 0x6D, 0xB7,
    0x14, 0x7F, 0x46, 0x8E, 0xEB, 0xA6, 0x74, 0xEA, 0x04, 0xA7, 0x63, 0x30,
    0x5B, 0xF1, 0xD3, 0x87, 0x07, 0xF6, 0x3D, 0xAD, 0xC3, 0x55, 0x01, 0x98,
    0x36, 0x99, 0x64, 0xFF, 0x73, 0xBF, 0xE8, 0x9F, 0x5D, 0x35, 0x14, 0xAD,
    0x1A, 0xAF, 0x00, 0xCF, 0x05, 0xFD, 0x62, 0xA4, 0x43, 0x97, 0x7D, 0x2C,
    0xEA, 0x2A, 0x5D, 0x2A, 0xD4, 0x78, 0x32, 0x7F, 0x97, 0x62, 0x12, 0x9A,
    0x8E, 0x76, 0x90, 0xF5, 0x9B, 0xD3, 0xC1, 0x3D, 0x1D, 0x88, 0x5E, 0x2E,
    0xDE, 0x6B, 0x20, 0x4E, 0xF5, 0x38, 0x2B, 0xED, 0x6F, 0x5F, 0xD6, 0x55,
    0xA6, 0x80, 0x2B, 0x1F, 0xF3, 0x71, 0x55, 0xE3, 0x0D, 0x26, 0x93, 0xB1,
    0x9E, 0x0E, 0xCB, 0xDE, 0xFE, 0xE0, 0xC4, 0x1C, 0x07, 0xD4, 0xDA, 0x2B,
    0x86, 0x46, 0xBE, 0xB1};

TestSuite(HMAC, .description = "HMAC");

uint8_t hmac_key[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
uint8_t data[] = {0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65};

uint8_t hmac_test_vector[][64] =
    // SHA-224
    {{0x89, 0x6f, 0xb1, 0x12, 0x8a, 0xbb, 0xdf, 0x19, 0x68, 0x32, 0x10, 0x7c, 0xd4, 0x9d, 0xf3, 0x3f, 0x47, 0xb4, 0xb1, 0x16, 0x99, 0x12, 0xba, 0x4f, 0x53, 0x68, 0x4b, 0x22},
     // SHA-256
     {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7},
     // SHA-384
     {0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4, 0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6, 0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9, 0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6},
     // SHA-512
     {0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, 0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, 0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54}};

uint8_t key[32] = {
    0x4E, 0x3D, 0x99, 0xBD, 0xA9, 0xDD, 0x42, 0x49, 0xFD, 0x38, 0x03, 0xD0,
    0x66, 0x0C, 0xCE, 0x49, 0x40, 0x1C, 0xB5, 0x5E, 0x3E, 0x4B, 0x13, 0x90,
    0xC2, 0x6C, 0x0E, 0x47, 0x79, 0x8E, 0xB8, 0x47};

int hmac_modes[] = {
    CW_HMAC_MD5,
    CW_HMAC_SHA_1,
    CW_HMAC_SHA_224,
    CW_HMAC_SHA_256,
    CW_HMAC_SHA_384,
    CW_HMAC_SHA_512,
    CW_HMAC_SHA_512_224,
    CW_HMAC_SHA_512_256,
    CW_HMAC_SHA3_224,
    CW_HMAC_SHA3_256,
    CW_HMAC_SHA3_384,
    CW_HMAC_SHA3_512,
    CW_HMAC_SM_3};

Test(HMAC, test_vector)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (cw_hmac_digest algorithm = CW_HMAC_SHA_224; algorithm <= CW_HMAC_SHA_512; algorithm++)
    {
        MAC_UNIT_TEST(cw_hmac_raw_ex(data, sizeof(data), hmac_key, sizeof(hmac_key), algorithm, &mac, &mac_len, 0),
                      != 1, END, "cw_hmac_raw_ex");

        CR_CW_UNIT_TEST_EXPECT(memcmp(mac, hmac_test_vector[algorithm - CW_HMAC_SHA_224], mac_len), != 0, END, 0,
                               "Mac is not equal to test vector -> Algorithm: %d", algorithm);

    END:
        if (mac == NULL)
            free(mac);
        mac = NULL;
    }
}

Test(HMAC, input_vector)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (int i = 0; i < sizeof(hmac_modes) / sizeof(hmac_modes[0]); i++)
    {
        cw_hmac_digest algorithm = hmac_modes[i];

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_hmac_raw_ex(input_vector, vector_length, key, sizeof(key), algorithm, &mac, &mac_len, 0),
                                   != 1, END, 0, "cw_hmac_raw_ex failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_verify(input_vector, vector_length, mac, mac_len, key, sizeof(key), algorithm),
                                   != 1, END, 0, "cw_hmac_verify failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(HMAC, input_vector_custom_output_size)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (int i = 0; i < sizeof(hmac_modes) / sizeof(hmac_modes[0]); i++)
    {
        cw_hmac_digest algorithm = hmac_modes[i];

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            mac_len = cw_fetch_hash_len_internal(algorithm) / 2;

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_raw_ex(input_vector, vector_length, key, sizeof(key), algorithm, &mac, &mac_len, MAC_SET_OUT_LEN),
                                   != 1, END, 0, "cw_hmac_raw_ex failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_verify(input_vector, vector_length, mac, mac_len, key, sizeof(key), algorithm),
                                   != 1, END, 0, "cw_hmac_verify failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(HMAC, input_vector_no_alloc)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (int i = 0; i < sizeof(hmac_modes) / sizeof(hmac_modes[0]); i++)
    {
        cw_hmac_digest algorithm = hmac_modes[i];

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            mac_len = cw_fetch_hash_len_internal(algorithm);

            mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
            CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "Calloc failed");

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_raw_ex(input_vector, vector_length, key, sizeof(key), algorithm, &mac, &mac_len, MAC_SET_OUT_LEN),
                                   != 1, END, 0, "cw_hmac_raw_ex failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_verify(input_vector, vector_length, mac, mac_len, key, sizeof(key), algorithm),
                                   != 1, END, 0, "cw_hmac_verify failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(HMAC, input_vector_no_alloc_custom_size)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (int i = 0; i < sizeof(hmac_modes) / sizeof(hmac_modes[0]); i++)
    {
        cw_hmac_digest algorithm = hmac_modes[i];

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            mac_len = cw_fetch_hash_len_internal(algorithm) / 2;

            mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
            CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "Calloc failed");

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_raw_ex(input_vector, vector_length, key, sizeof(key), algorithm, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_SET_OUT_LEN),
                                   != 1, END, 0, "cw_hmac_raw_ex failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_verify(input_vector, vector_length, mac, mac_len, key, sizeof(key), algorithm),
                                   != 1, END, 0, "cw_hmac_verify failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(HMAC, input_vector_wrong_key_length)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (int i = 0; i < sizeof(hmac_modes) / sizeof(hmac_modes[0]); i++)
    {
        cw_hmac_digest algorithm = hmac_modes[i];

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_hmac_raw_ex(input_vector, vector_length, key, sizeof(key), algorithm, &mac, &mac_len, 0),
                                   != 1, END, 0, "cw_hmac_raw_ex failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

            CR_CW_UNIT_TEST_EXPECT(cw_hmac_verify(input_vector, vector_length, mac, mac_len, key, sizeof(key) - 1, algorithm),
                                   != 0, END, 1, "cw_hmac_verify should have failed --- vector length: %lu --- algorithm: %lu", vector_length, algorithm);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

TestSuite(CMAC, .description = "CMAC");

int cmac_modes[] = {
    CW_CMAC_AES_128_ECB,
    CW_CMAC_AES_128_CBC,
    CW_CMAC_AES_192_ECB,
    CW_CMAC_AES_192_CBC,
    CW_CMAC_AES_256_ECB,
    CW_CMAC_AES_256_CBC,
    CW_CMAC_ARIA_128_ECB,
    CW_CMAC_ARIA_128_CBC,
    CW_CMAC_ARIA_192_ECB,
    CW_CMAC_ARIA_192_CBC,
    CW_CMAC_ARIA_256_ECB,
    CW_CMAC_ARIA_256_CBC,
    CW_CMAC_CAMELLIA_128_ECB,
    CW_CMAC_CAMELLIA_128_CBC,
    CW_CMAC_CAMELLIA_192_ECB,
    CW_CMAC_CAMELLIA_192_CBC,
    CW_CMAC_CAMELLIA_256_ECB,
    CW_CMAC_CAMELLIA_256_CBC};

Test(CMAC, no_mac_length)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (cw_cmac_cipher i = 0; i <= sizeof(cmac_modes) / sizeof(cmac_modes[0]); i++)
    {
        cw_cmac_cipher cipher = cmac_modes[i];
        uint32_t key_length;

        CR_CW_UNIT_TEST_EXPECT(cw_fetch_symmetric_cipher_key_and_iv_length(cipher, (int *)&key_length, NULL),
                               != 1, END, 0, "%s", "cw_fetch_symmetric_cipher_key_and_iv_length failed");

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_cmac_raw_ex(input_vector, vector_length, key, key_length, cipher, &mac, &mac_len, 0),
                                   != 1, END, 0, "cw_cmac_raw_ex failed --- vector length: %lu --- cipher: %d", vector_length, cipher);

            CR_CW_UNIT_TEST_EXPECT(cw_cmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, cipher),
                                   != 1, END, 0, "cw_cmac_verify failed --- vector length: %lu --- algorithm: %d", vector_length, cipher);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(CMAC, no_mac_length_no_alloc)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (cw_cmac_cipher i = 0; i <= sizeof(cmac_modes) / sizeof(cmac_modes[0]); i++)
    {
        cw_cmac_cipher cipher = cmac_modes[i];
        uint32_t key_length;

        CR_CW_UNIT_TEST_EXPECT(cw_fetch_symmetric_cipher_key_and_iv_length(cipher, (int *)&key_length, NULL),
                               != 1, END, 0, "%s", "cw_fetch_symmetric_cipher_key_and_iv_length failed");

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            mac = OPENSSL_zalloc(16);
            CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "Calloc failed");

            CR_CW_UNIT_TEST_EXPECT(cw_cmac_raw_ex(input_vector, vector_length, key, key_length, cipher, &mac, &mac_len, MAC_NO_ALLOC),
                                   != 1, END, 0, "cw_cmac_raw_ex failed --- vector length: %lu --- cipher: %d", vector_length, cipher);

            CR_CW_UNIT_TEST_EXPECT(cw_cmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, cipher),
                                   != 1, END, 0, "cw_cmac_verify failed --- vector length: %lu --- algorithm: %d", vector_length, cipher);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(CMAC, no_mac_custom_output_size)
{
    uint8_t *mac = NULL;

    for (cw_cmac_cipher i = 0; i <= sizeof(cmac_modes) / sizeof(cmac_modes[0]); i++)
    {
        cw_cmac_cipher cipher = cmac_modes[i];
        uint32_t key_length;

        CR_CW_UNIT_TEST_EXPECT(cw_fetch_symmetric_cipher_key_and_iv_length(cipher, (int *)&key_length, NULL),
                               != 1, END, 0, "%s", "cw_fetch_symmetric_cipher_key_and_iv_length failed");

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            for (uint64_t mac_len = 1; mac_len < 16; mac_len++)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_cmac_raw_ex(input_vector, vector_length, key, key_length, cipher, &mac, &mac_len, MAC_SET_OUT_LEN),
                                       != 1, END, 0, "cw_cmac_raw_ex failed --- vector length: %lu --- cipher: %d", vector_length, cipher);

                CR_CW_UNIT_TEST_EXPECT(cw_cmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, cipher),
                                       != 1, END, 0, "cw_cmac_verify failed --- vector length: %lu --- algorithm: %d", vector_length, cipher);
            }
        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(CMAC, no_mac_custom_output_size_no_alloc)
{
    uint8_t *mac = NULL;

    for (cw_cmac_cipher i = 0; i <= sizeof(cmac_modes) / sizeof(cmac_modes[0]); i++)
    {
        cw_cmac_cipher cipher = cmac_modes[i];
        uint32_t key_length;

        CR_CW_UNIT_TEST_EXPECT(cw_fetch_symmetric_cipher_key_and_iv_length(cipher, (int *)&key_length, NULL),
                               != 1, END, 0, "%s", "cw_fetch_symmetric_cipher_key_and_iv_length failed");

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            for (uint64_t mac_len = 1; mac_len < 16; mac_len++)
            {
                mac = OPENSSL_zalloc(mac_len);
                CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "Calloc failed");

                CR_CW_UNIT_TEST_EXPECT(cw_cmac_raw_ex(input_vector, vector_length, key, key_length, cipher, &mac, &mac_len, MAC_SET_OUT_LEN),
                                       != 1, END, 0, "cw_cmac_raw_ex failed --- vector length: %lu --- cipher: %d", vector_length, cipher);

                CR_CW_UNIT_TEST_EXPECT(cw_cmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, cipher),
                                       != 1, END, 0, "cw_cmac_verify failed --- vector length: %lu --- algorithm: %d", vector_length, cipher);
            }
        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

Test(CMAC, input_vector_wrong_key_len)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    for (cw_cmac_cipher i = 0; i <= sizeof(cmac_modes) / sizeof(cmac_modes[0]); i++)
    {
        cw_cmac_cipher cipher = cmac_modes[i];
        uint32_t key_length;

        CR_CW_UNIT_TEST_EXPECT(cw_fetch_symmetric_cipher_key_and_iv_length(cipher, (int *)&key_length, NULL),
                               != 1, END, 0, "%s", "cw_fetch_symmetric_cipher_key_and_iv_length failed");

        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_cmac_raw_ex(input_vector, vector_length, key, key_length, cipher, &mac, &mac_len, MAC_SET_OUT_LEN),
                                   != 1, END, 0, "cw_cmac_raw_ex failed --- vector length: %lu --- cipher: %d", vector_length, cipher);

            CR_CW_UNIT_TEST_EXPECT(cw_cmac_verify(input_vector, vector_length, mac, mac_len, key, key_length - 1, cipher),
                                   != 0, END, 1, "cw_cmac_verify should have failed --- vector length: %lu --- algorithm: %d", vector_length, cipher);

        END:
            if (mac == NULL)
                free(mac);
            mac = NULL;
        }
    }
}

TestSuite(GMAC, .description = "GMAC");

uint8_t iv[] = {0x23, 0x9B, 0x9F, 0x7F, 0xE3, 0x9C, 0xC1, 0xA7, 0x6B, 0x55, 0x56, 0x87,
                0x8D, 0x97, 0x06, 0x66, 0x13, 0x59, 0xE7, 0x85, 0xDA, 0x4B, 0xF1, 0xA9,
                0xF9, 0xD0, 0x7A, 0x28, 0xC6, 0x85, 0xE7, 0x80, 0xB0, 0xB6, 0x0F, 0x36,
                0xC3, 0x11, 0xED, 0x56, 0x9A, 0xB3, 0xE3, 0x9D, 0xA5, 0xEF, 0x29, 0x2D,
                0xC3, 0x6B, 0xB0, 0x4A, 0x46, 0x30, 0x6D, 0xDC, 0x12, 0x8B, 0x98, 0x18,
                0x8C, 0x9B, 0x6A, 0xF9, 0x95, 0x73, 0xA6, 0xEC, 0x6C, 0x50, 0xF9, 0x98,
                0x83, 0x3D, 0xF7, 0xC3, 0x62, 0x3E, 0xFD, 0x1B};

Test(GMAC, input_vector)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 0;

    int key_length;

    for (int mode = CW_GMAC_AES_GCM_128; mode <= CW_GMAC_AES_GCM_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_fetch_aead_key_and_iv_length_internal(mode, &key_length, NULL), != 1, END, 0, "%s", "cw_fetch_aead_key_and_iv_length_internal failed");

            for (uint32_t iv_len = 1; iv_len < sizeof(iv); iv_len++)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_gmac_raw_ex(input_vector, vector_length, key, key_length, iv, iv_len, mode, &mac, &mac_len, 0),
                                       != 1, END, 0, "cw_gmac_raw_ex failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, iv, iv_len, mode),
                                       != 1, END, 0, "cw_gmac_verify failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(GMAC, input_vector_custom_output_size)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 8;

    int key_length;

    for (int mode = CW_GMAC_AES_GCM_128; mode <= CW_GMAC_AES_GCM_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_fetch_aead_key_and_iv_length_internal(mode, &key_length, NULL), != 1, END, 0, "%s", "cw_fetch_aead_key_and_iv_length_internal failed");

            for (uint32_t iv_len = 1; iv_len < sizeof(iv); iv_len++)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_gmac_raw_ex(input_vector, vector_length, key, key_length, iv, iv_len, mode, &mac, &mac_len, MAC_SET_OUT_LEN),
                                       != 1, END, 0, "cw_gmac_raw_ex failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, iv, iv_len, mode),
                                       != 1, END, 0, "cw_gmac_verify failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(GMAC, input_vector_no_alloc)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 8;

    int key_length;

    for (int mode = CW_GMAC_AES_GCM_128; mode <= CW_GMAC_AES_GCM_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_fetch_aead_key_and_iv_length_internal(mode, &key_length, NULL), != 1, END, 0, "%s", "cw_fetch_aead_key_and_iv_length_internal failed");

            for (uint32_t iv_len = 1; iv_len < sizeof(iv); iv_len++)
            {
                mac = OPENSSL_zalloc(16 * sizeof(uint8_t));
                CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_raw_ex(input_vector, vector_length, key, key_length, iv, iv_len, mode, &mac, &mac_len, MAC_NO_ALLOC),
                                       != 1, END, 0, "cw_gmac_raw_ex failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, iv, iv_len, mode),
                                       != 1, END, 0, "cw_gmac_verify failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(GMAC, input_vector_no_alloc_custom_size)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 12;

    int key_length;

    for (int mode = CW_GMAC_AES_GCM_128; mode <= CW_GMAC_AES_GCM_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_fetch_aead_key_and_iv_length_internal(mode, &key_length, NULL), != 1, END, 0, "%s", "cw_fetch_aead_key_and_iv_length_internal failed");

            for (uint32_t iv_len = 1; iv_len < sizeof(iv); iv_len++)
            {
                mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
                CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_raw_ex(input_vector, vector_length, key, key_length, iv, iv_len, mode, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_SET_OUT_LEN),
                                       != 1, END, 0, "cw_gmac_raw_ex failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, iv, iv_len, mode),
                                       != 1, END, 0, "cw_gmac_verify failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(GMAC, input_vector_wrong_key)
{
    uint8_t *mac = NULL;
    uint64_t mac_len = 12;

    int key_length;

    for (int mode = CW_GMAC_AES_GCM_128; mode <= CW_GMAC_AES_GCM_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            CR_CW_UNIT_TEST_EXPECT(cw_fetch_aead_key_and_iv_length_internal(mode, &key_length, NULL), != 1, END, 0, "%s", "cw_fetch_aead_key_and_iv_length_internal failed");

            for (uint32_t iv_len = 1; iv_len < sizeof(iv); iv_len++)
            {
                mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
                CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_raw_ex(input_vector, vector_length, key, key_length, iv, iv_len, mode, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_SET_OUT_LEN),
                                       != 1, END, 0, "cw_gmac_raw_ex failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));

                CR_CW_UNIT_TEST_EXPECT(cw_gmac_verify(input_vector, vector_length, mac, mac_len, key, key_length - 1, iv, iv_len, mode),
                                       != 0, END, 1, "cw_gmac_verify should have failed --- vector length: %lu --- algorithm: %s", vector_length, cw_fetch_aead_str_internal(mode));
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

TestSuite(SIPHASH, .description = "SIPHASH");

Test(SIPHASH, input_vector)
{
    uint8_t *mac = NULL;
    uint32_t mac_len = 0;

    uint32_t key_length = 16;

    for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
    {
        for (uint32_t comp_rounds = 1; comp_rounds < 4; comp_rounds++)
        {
            for (uint32_t final_rounds = 1; final_rounds < 8; final_rounds++)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, 0),
                                       != 1, END, 0, "cw_siphash_raw_ex failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                CR_CW_UNIT_TEST_EXPECT(cw_siphash_verify(input_vector, vector_length, mac, mac_len, key, key_length, comp_rounds, final_rounds),
                                       != 1, END, 0, "cw_siphash_verify failed --- vector length: %lu --- c_rounds: %u --- f_rounds: %u", vector_length, comp_rounds, final_rounds);
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(SIPHASH, input_vector_no_alloc)
{
    uint8_t *mac = NULL;
    uint32_t mac_len = 0;

    uint32_t key_length = 16;

    for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
    {
        for (uint32_t comp_rounds = 1; comp_rounds < 4; comp_rounds++)
        {
            for (uint32_t final_rounds = 1; final_rounds < 8; final_rounds++)
            {
                mac = OPENSSL_zalloc(16 * sizeof(uint8_t));
                CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_NO_ALLOC),
                                       != 1, END, 0, "cw_siphash_raw_ex failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                CR_CW_UNIT_TEST_EXPECT(cw_siphash_verify(input_vector, vector_length, mac, mac_len, key, key_length, comp_rounds, final_rounds),
                                       != 1, END, 0, "cw_siphash_verify failed --- vector length: %lu --- c_rounds: %u --- f_rounds: %u", vector_length, comp_rounds, final_rounds);
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(SIPHASH, input_vector_custom_output_size)
{
    uint8_t *mac = NULL;

    uint32_t key_length = 16;

    for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
    {
        for (uint32_t mac_len = 0; mac_len <= 16; mac_len++)
        {
            for (uint32_t comp_rounds = 1; comp_rounds < 4; comp_rounds++)
            {
                for (uint32_t final_rounds = 1; final_rounds < 8; final_rounds++)
                {
                    if (mac_len != 8 && mac_len != 16)
                    {
                        CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN),
                                               != 0, END, 1, "cw_siphash_raw_ex should have failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                        goto END;
                    }
                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN),
                                           != 1, END, 0, "cw_siphash_raw_ex failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_verify(input_vector, vector_length, mac, mac_len, key, key_length, comp_rounds, final_rounds),
                                           != 1, END, 0, "cw_siphash_verify failed --- vector length: %lu --- c_rounds: %u --- f_rounds: %u", vector_length, comp_rounds, final_rounds);
                END:
                    if (mac == NULL)
                        free(mac);
                    mac = NULL;
                }
            }
        }
    }
}

Test(SIPHASH, input_vector_custom_output_size_no_alloc)
{
    uint8_t *mac = NULL;

    uint32_t key_length = 16;

    for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
    {
        for (uint32_t mac_len = 1; mac_len <= 16; mac_len++)
        {
            for (uint32_t comp_rounds = 1; comp_rounds < 4; comp_rounds++)
            {
                for (uint32_t final_rounds = 1; final_rounds < 8; final_rounds++)
                {
                    mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
                    CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                    if (mac_len != 8 && mac_len != 16)
                    {
                        CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_NO_ALLOC),
                                               != 0, END, 1, "cw_siphash_raw_ex should have failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                        goto END;
                    }
                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_NO_ALLOC),
                                           != 1, END, 0, "cw_siphash_raw_ex failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_verify(input_vector, vector_length, mac, mac_len, key, key_length, comp_rounds, final_rounds),
                                           != 1, END, 0, "cw_siphash_verify failed --- vector length: %lu --- c_rounds: %u --- f_rounds: %u", vector_length, comp_rounds, final_rounds);
                END:
                    if (mac == NULL)
                        free(mac);
                    mac = NULL;
                }
            }
        }
    }
}

Test(SIPHASH, input_vector_custom_output_size_no_alloc_wrong_key)
{
    uint8_t *mac = NULL;

    uint32_t key_length = 16;

    for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
    {
        for (uint32_t mac_len = 1; mac_len <= 16; mac_len++)
        {
            for (uint32_t comp_rounds = 1; comp_rounds < 4; comp_rounds++)
            {
                for (uint32_t final_rounds = 1; final_rounds < 8; final_rounds++)
                {
                    mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
                    CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                    if (mac_len != 8 && mac_len != 16)
                    {
                        CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_NO_ALLOC),
                                               != 0, END, 1, "cw_siphash_raw_ex should have failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                        goto END;
                    }
                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_raw_ex(input_vector, vector_length, key, key_length, comp_rounds, final_rounds, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_NO_ALLOC),
                                           != 1, END, 0, "cw_siphash_raw_ex failed --- vector length: %lu --- c_rounds: %u --- f_rounds %u", vector_length, comp_rounds, final_rounds);

                    CR_CW_UNIT_TEST_EXPECT(cw_siphash_verify(input_vector, vector_length, mac, mac_len, key, key_length - 1, comp_rounds, final_rounds),
                                           != 0, END, 1, "cw_siphash_verify should have failed --- vector length: %lu --- c_rounds: %u --- f_rounds: %u", vector_length, comp_rounds, final_rounds);
                END:
                    if (mac == NULL)
                        free(mac);
                    mac = NULL;
                }
            }
        }
    }
}

TestSuite(KMAC, .description = "KMAC");

uint8_t info[] = {
    0x79, 0x3D, 0x79, 0x8A, 0x04, 0x37, 0xD5, 0x14, 0xC7, 0x2F, 0x39, 0x48,
    0x26, 0x77, 0xC9, 0x6E, 0xEB, 0x34, 0x31, 0x5D, 0xB4, 0x0C, 0x28, 0xAE,
    0xFF, 0x5E, 0xDA, 0xFC, 0xC7, 0xA6, 0x26, 0x15, 0xD7, 0x55, 0x21, 0x71,
    0xF5, 0xB2, 0x2B, 0x64, 0xB8, 0x0C, 0xC6, 0x47, 0xD5, 0x90, 0xAE, 0x13,
    0xA0, 0x08, 0x38, 0x8A, 0xEB, 0xEF, 0xD0, 0xC9, 0x99, 0x45, 0x59, 0x31,
    0xA6, 0xB2, 0xD2, 0xCB, 0x93, 0x83, 0x2F, 0x9B, 0x39, 0x85, 0x4A, 0x9C,
    0x70, 0xB5, 0x65, 0xA5, 0x72, 0x2D, 0x9B, 0xA5, 0x49, 0x55, 0x25, 0x86,
    0x14, 0x88, 0xA3, 0x9D, 0x75, 0x66, 0x07, 0xA2, 0x80, 0x1A, 0xB6, 0x2A,
    0xAF, 0x71, 0xF1, 0x1D, 0x29, 0xAC, 0x38, 0xD9, 0xAC, 0x9C, 0x98, 0xE9,
    0xA8, 0x47, 0x99, 0xA4, 0xDC, 0xAE, 0xC6, 0x2F, 0x6E, 0x64, 0xBA, 0x85,
    0x8B, 0x92, 0x66, 0x1F, 0xD2, 0x60, 0x0D, 0xF9, 0x8F, 0xF8, 0xF5, 0x3D,
    0x83, 0x04, 0xA4, 0xF9, 0x94, 0x98, 0x4F, 0x2B, 0x58, 0x82, 0x3B, 0x60,
    0x89, 0x2C, 0x9B, 0x15, 0x8D, 0xED, 0x63, 0x52, 0x88, 0x75, 0x11, 0xF1,
    0x39, 0x97, 0x10, 0xC3, 0x34, 0x38, 0xFE, 0x49, 0x6F, 0x19, 0x41, 0x91,
    0x07, 0x0C, 0xB9, 0x24, 0x9E, 0x02, 0x7E, 0x8A, 0x1E, 0x60, 0x60, 0x1C,
    0xAB, 0x3C, 0x42, 0x19, 0xBF, 0x83, 0x62, 0x72, 0xEA, 0x77, 0x17, 0x1C,
    0x98, 0x21, 0x47, 0x85, 0x8C, 0xEF, 0x18, 0x5A, 0xAE, 0x3A, 0x7B, 0x9E,
    0x49, 0x29, 0x4E, 0x4D, 0x46, 0xC3, 0xB1, 0xE5, 0xF0, 0x80, 0x62, 0xED,
    0xC1, 0xD6, 0xD7, 0xAC, 0x1E, 0xB9, 0x27, 0xC4, 0x99, 0x11, 0x98, 0x73,
    0x3E, 0x66, 0xAE, 0xED, 0x41, 0x1C, 0x97, 0x41, 0xD7, 0x05, 0xCA, 0xB8,
    0x0D, 0x9F, 0x41, 0x85, 0x9E, 0x47, 0x3F, 0x05, 0x5D, 0x39, 0xD9, 0x08,
    0x9E, 0xD0, 0x03, 0x3B, 0x4E, 0x3D, 0x99, 0xBD, 0xA9, 0xDD, 0x42, 0x49,
    0xFD, 0x38, 0x03, 0xD0, 0x66, 0x0C, 0xCE, 0x49, 0x40, 0x1C, 0xB5, 0x5E,
    0x3E, 0x4B, 0x13, 0x90, 0xC2, 0x6C, 0x0E, 0x47, 0x79, 0x8E, 0xB8, 0x47,
    0x25, 0xC9, 0x0B, 0xDE, 0xDF, 0xD2, 0x29, 0x32, 0x70, 0xCA, 0x0B, 0xDC,
    0xD6, 0xB7, 0x75, 0x2A, 0x18, 0xE1, 0x86, 0x52, 0x0F, 0x05, 0x8C, 0x5C,
    0x51, 0x73, 0x60, 0x3B, 0xE7, 0x42, 0xCB, 0x67, 0xC1, 0x6B, 0xF7, 0x6D,
    0xB0, 0x2E, 0x0E, 0xBC, 0xDA, 0xCD, 0xA6, 0xA1, 0x7E, 0x01, 0xA8, 0x27,
    0xBD, 0xE5, 0xE5, 0x7E, 0xB4, 0xFA, 0x8D, 0xCD, 0xAD, 0xF4, 0x94, 0x3B,
    0xFA, 0xA7, 0x0A, 0x5D, 0x8C, 0x43, 0xE1, 0x1E, 0x2C, 0x46, 0x8B, 0x57,
    0xB5, 0x9E, 0xB0, 0xE0, 0x3F, 0x9D, 0xE7, 0xC2, 0x66, 0x0A, 0xA7, 0x02,
    0xEE, 0xB4, 0xCC, 0xBA, 0xC2, 0xDD, 0x43, 0x7F, 0x1B, 0xB7, 0x8D, 0x5C,
    0xD2, 0x20, 0xAD, 0x12, 0x16, 0xDB, 0xFD, 0xD2, 0x94, 0xEB, 0x71, 0x5A,
    0x75, 0x75, 0x2C, 0xD3, 0x18, 0x29, 0xCC, 0x44, 0xB0, 0x9D, 0xFC, 0x0F,
    0xD2, 0x30, 0x66, 0x42, 0xB4, 0xC7, 0x32, 0x92, 0xE5, 0x9E, 0x91, 0xAD,
    0x19, 0x33, 0x83, 0xA1, 0xED, 0x61, 0xE7, 0xF0, 0x06, 0x3C, 0x14, 0x7D,
    0x8D, 0xBD, 0x9B, 0x0C, 0x1E, 0x3C, 0x87, 0x22, 0xE1, 0xB8, 0xCF, 0xD2,
    0xD4, 0xF7, 0x07, 0xFC, 0xDE, 0xFF, 0xE3, 0xA8, 0x60, 0x50, 0x73, 0xA9,
    0xB0, 0x21, 0x38, 0x0F, 0x00, 0xCC, 0x84, 0x6B, 0x45, 0xC0, 0xBA, 0xB0,
    0x51, 0xD8, 0x05, 0xBD, 0xEA, 0x1F, 0xCB, 0x1D, 0xC6, 0x8F, 0xFB, 0xEE,
    0x43, 0x98, 0x36, 0x69, 0x2E, 0xE1, 0x2C, 0x57, 0x64, 0xB8, 0x54, 0x1A,
    0xFB, 0x72, 0x95, 0x6F, 0xDE, 0x1C, 0xFD, 0x37, 0x16, 0xAD, 0x62, 0x6A,
    0x18, 0xAB, 0x9B, 0xDC, 0x7E, 0x2A, 0x32, 0x07, 0xC9, 0x2B, 0x6B, 0xC1,
    0x05, 0x42, 0x3E, 0x62, 0x14, 0xFA, 0x56, 0xAC, 0x69, 0x96, 0x23, 0xB0,
    0xE2, 0x2A, 0x2E, 0xFB, 0x63, 0x33, 0x2F, 0xFB, 0x58, 0xDB, 0xF2, 0xFA,
    0x4E, 0xA6, 0x7B, 0x5C, 0x63, 0x45, 0x70, 0xC1, 0x98, 0x27, 0x12, 0x48,
    0xF6, 0xD9, 0x7E, 0x47, 0x1E, 0x80, 0x48, 0x96, 0x06, 0xC6, 0x74, 0xDF,
    0x7C, 0x2F, 0xAD, 0xB6, 0xB5, 0xF6, 0xE6, 0xB8, 0xBB, 0x00, 0xD0, 0x8E};

Test(KMAC, input_vector)
{
    uint8_t *mac = NULL;
    uint32_t mac_len = 0;

    for (int mode = CW_KMAC_128; mode <= CW_KMAC_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length++)
        {
            for (uint32_t key_length = 4; key_length < sizeof(key); key_length++)
            {
                CR_CW_UNIT_TEST_EXPECT(cw_kmac_raw_ex(input_vector, vector_length, key, key_length, mode, NULL, 0, &mac, &mac_len, 0),
                                       != 1, END, 0, "cw_kmac_raw_ex failed --- vector length: %lu --- mode: %d --- key_length: %u", vector_length, mode, key_length);

                CR_CW_UNIT_TEST_EXPECT(cw_kmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, NULL, 0, mode),
                                       != 1, END, 0, "cw_kmac_verify failed --- vector length: %lu --- mode: %d --- key_length: %u", vector_length, mode, key_length);
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(KMAC, input_vector_no_alloc)
{
    uint8_t *mac = NULL;
    uint32_t mac_len = 0;

    for (int mode = CW_KMAC_128; mode <= CW_KMAC_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < 4; vector_length++)
        {
            for (uint32_t key_length = 4; key_length < sizeof(key); key_length++)
            {
                if (mode == CW_KMAC_128)
                {
                    mac = OPENSSL_zalloc(32 * sizeof(uint8_t));
                    CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");
                }
                else
                {
                    mac = OPENSSL_zalloc(64 * sizeof(uint8_t));
                    CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");
                }

                CR_CW_UNIT_TEST_EXPECT(cw_kmac_raw_ex(input_vector, vector_length, key, key_length, mode, NULL, 0, &mac, &mac_len, MAC_NO_ALLOC),
                                       != 1, END, 0, "cw_kmac_raw_ex failed --- vector length: %lu --- mode: %d --- key_length: %u", vector_length, mode, key_length);

                CR_CW_UNIT_TEST_EXPECT(cw_kmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, NULL, 0, mode),
                                       != 1, END, 0, "cw_kmac_verify failed --- vector length: %lu --- mode: %d --- key_length: %u", vector_length, mode, key_length);
            END:
                if (mac == NULL)
                    free(mac);
                mac = NULL;
            }
        }
    }
}

Test(KMAC, input_vector_custom_size)
{
    uint8_t *mac = NULL;

    for (int mode = CW_KMAC_128; mode <= CW_KMAC_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length *= 2)
        {
            for (uint32_t key_length = 4; key_length < sizeof(key); key_length++)
            {
                for (uint32_t mac_len = 1; mac_len < 100; mac_len++)
                {
                    CR_CW_UNIT_TEST_EXPECT(cw_kmac_raw_ex(input_vector, vector_length, key, key_length, mode, NULL, 0, &mac, &mac_len, MAC_SET_OUT_LEN),
                                           != 1, END, 0, "cw_kmac_raw_ex failed --- vector length: %lu --- mode: %d --- key_length: %u --- output_length: %u",
                                           vector_length, mode, key_length, mac_len);

                    CR_CW_UNIT_TEST_EXPECT(cw_kmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, NULL, 0, mode),
                                           != 1, END, 0, "cw_kmac_verify failed --- vector length: %lu --- mode: %d --- key_length: %u --- output_length: %u",
                                           vector_length, mode, key_length, mac_len);
                END:
                    if (mac == NULL)
                        free(mac);
                    mac = NULL;
                }
            }
        }
    }
}

Test(KMAC, input_vector_custom_size_no_alloc)
{
    uint8_t *mac = NULL;

    for (int mode = CW_KMAC_128; mode <= CW_KMAC_256; mode++)
    {
        for (uint64_t vector_length = 1; vector_length < sizeof(input_vector); vector_length *= 2)
        {
            for (uint32_t key_length = 4; key_length < sizeof(key); key_length++)
            {
                for (uint32_t mac_len = 1; mac_len < 100; mac_len++)
                {
                    mac = OPENSSL_zalloc(mac_len * sizeof(uint8_t));
                    CR_CW_UNIT_TEST_EXPECT(mac != NULL, != 1, END, 0, "%s", "OPENSSL_zalloc failed");

                    CR_CW_UNIT_TEST_EXPECT(cw_kmac_raw_ex(input_vector, vector_length, key, key_length, mode, NULL, 0, &mac, &mac_len, MAC_SET_OUT_LEN | MAC_NO_ALLOC),
                                           != 1, END, 0, "cw_kmac_raw_ex failed --- vector length: %lu --- mode: %d --- key_length: %u --- output_length: %u",
                                           vector_length, mode, key_length, mac_len);

                    CR_CW_UNIT_TEST_EXPECT(cw_kmac_verify(input_vector, vector_length, mac, mac_len, key, key_length, NULL, 0, mode),
                                           != 1, END, 0, "cw_kmac_verify failed --- vector length: %lu --- mode: %d --- key_length: %u --- output_length: %u",
                                           vector_length, mode, key_length, mac_len);
                END:
                    if (mac == NULL)
                        free(mac);
                    mac = NULL;
                }
            }
        }
    }
}
