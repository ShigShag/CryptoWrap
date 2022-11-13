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
#include <internal/symmetric_cipher_internal.h>
#include <internal/unit_test/cw_uint_test_internal.h>

#include <cryptowrap/random.h>
#include <cryptowrap/hash.h>

#include <cryptowrap/error.h>

unsigned char key[64] = {
    0xB3, 0x97, 0x46, 0x3D, 0x20, 0xC9, 0x28, 0x47, 0xDC, 0xE4, 0x44, 0x61,
    0x9A, 0x94, 0x47, 0xF9, 0xCC, 0x2D, 0xB8, 0xDD, 0x43, 0x2E, 0x4C, 0xE7,
    0xCA, 0x19, 0xF7, 0x50, 0x7D, 0x22, 0xD9, 0xB9, 0x81, 0x20, 0x28, 0xF0,
    0xB9, 0xF8, 0xF2, 0x39, 0x9A, 0x0C, 0x2F, 0x6F, 0xCC, 0x6F, 0xEF, 0x7C,
    0xAC, 0x64, 0x98, 0x17, 0x90, 0x36, 0xB4, 0x30, 0xE0, 0x9D, 0x62, 0x1B,
    0xBB, 0x20, 0x41, 0xF8};

unsigned char iv[32] = {
    0xCA, 0xA9, 0xEE, 0x59, 0x79, 0xB4, 0x7A, 0x95, 0x40, 0xFF, 0xF0, 0xE1,
    0x77, 0x21, 0x65, 0xD1, 0xE2, 0x22, 0x36, 0x69, 0x06, 0x8C, 0xAB, 0x80,
    0x46, 0xC0, 0x32, 0xB9, 0x1A, 0xBD, 0xA9, 0xEF};

unsigned char test_vector[] = {
    0xCA, 0xA9, 0xEE, 0x59, 0x79, 0xB4, 0x7A, 0x95, 0x40, 0xFF, 0xF0, 0xE1,
    0x77, 0x21, 0x65, 0xD1, 0xE2, 0x22, 0x36, 0x69, 0x06, 0x8C, 0xAB, 0x80,
    0x46, 0xC0, 0x32, 0xB9, 0x1A, 0xBD, 0xA9, 0xEF, 0xAF, 0x61, 0x38, 0x07,
    0x41, 0x6D, 0x0C, 0x21, 0xEC, 0x48, 0xBE, 0xF2, 0xDF, 0x72, 0xB6, 0xE4,
    0xC2, 0x1C, 0x1A, 0x74, 0x28, 0xC3, 0x6D, 0x20, 0x6F, 0xDD, 0x88, 0x9D,
    0x6E, 0xC7, 0x68, 0xA2, 0x58, 0x02, 0x45, 0x20, 0x40, 0x0A, 0xB8, 0xB5,
    0xAF, 0x62, 0x5E, 0x6F, 0x3E, 0x26, 0x96, 0x60, 0xA1, 0x92, 0xD3, 0x10,
    0x7A, 0x8C, 0x8A, 0x56, 0x2D, 0x24, 0x38, 0x29, 0x08, 0x3B, 0xD5, 0xCE,
    0xC3, 0x04, 0x3F, 0x33, 0x69, 0x05, 0xE0, 0x6F, 0x07, 0x3E, 0x6B, 0x12,
    0xE9, 0x96, 0x35, 0xC8, 0xDB, 0xB1, 0x3B, 0x59, 0x50, 0x91, 0xCB, 0x92,
    0x4F, 0x35, 0x07, 0x0A, 0xF1, 0xB4, 0xA5, 0xCA, 0x08, 0x1E, 0xF0, 0x0D,
    0xFE, 0x6A, 0x3A, 0x00, 0x2C, 0x3D, 0x84, 0x28, 0x35, 0x6A, 0xBE, 0xEC,
    0xB2, 0x03, 0xEB, 0x2A, 0xA7, 0xDE, 0x7F, 0x39, 0xF8, 0x74, 0x31, 0x07,
    0x85, 0x7B, 0x31, 0x62, 0x6A, 0x0E, 0x03, 0x2C, 0xD6, 0x99, 0x24, 0x2E,
    0x5E, 0x94, 0x4D, 0x4D, 0x88, 0x6F, 0xB7, 0xBE, 0xA9, 0x1B, 0x36, 0xF7,
    0x9D, 0x28, 0x2E, 0x08, 0xEB, 0x6A, 0x2D, 0x41, 0x3F, 0xF1, 0x74, 0x12,
    0x63, 0x0B, 0x14, 0x8F, 0xF9, 0xF0, 0xF4, 0x87, 0xE0, 0xEF, 0x70, 0x4D,
    0x3B, 0xB4, 0xB9, 0x7B, 0x16, 0x23, 0x6D, 0xD9, 0xF4, 0xE1, 0xC2, 0xEB,
    0xF4, 0x1F, 0xC1, 0x9A, 0x04, 0xED, 0x07, 0x09, 0xC0, 0x61, 0x34, 0x99,
    0xCA, 0x98, 0xD3, 0x9D, 0xED, 0xBF, 0x14, 0x42, 0x72, 0xD1, 0x1C, 0x48,
    0x80, 0x2C, 0x41, 0x53, 0x48, 0x4A, 0x48, 0xAC, 0x83, 0x12, 0xA0, 0xE0};

#define SYM_CIPHER_UNIT_TEST(func_call, fail_condition, end_point, algorithm_id, function_str)   \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- algorithm_id: %s\n", \
                           function_str, cw_fetch_symmetric_cipher_str_internal(algorithm_id))

#define SYM_CIPHER_UNIT_TEST_SUPPOSE_FAIL(func_call, fail_condition, end_point, algorithm_id, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- algorithm_id: %s\n",            \
                           function_str, cw_fetch_symmetric_cipher_str_internal(algorithm_id))

#define SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(func_call, fail_condition, end_point, algorithm_id, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 0, "%s --- algorithm_id: %s --- vector_size: %d\n",    \
                           function_str, cw_fetch_symmetric_cipher_str_internal(algorithm_id), vector_size)

#define SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(func_call, fail_condition, end_point, algorithm_id, vector_size, function_str) \
    CR_CW_UNIT_TEST_EXPECT(func_call, fail_condition, end_point, 1, "%s --- algorithm_id: %s --- vector_size: %d\n",                 \
                           function_str, cw_fetch_symmetric_cipher_str_internal(algorithm_id), vector_size)

TestSuite(Raw, .description = "Raw Interface");

Test(Raw, CW_cipher_raw_encrypt_bytes_block_size)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    uint64_t test_vector_len = 16;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
        SYM_CIPHER_UNIT_TEST(key_len, == 0, END, algorithm_id, "cw_sym_cipher_get_key_length");
        uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

        SYM_CIPHER_UNIT_TEST(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                             == 0, END, algorithm_id, "cw_sym_cipher_raw_encrypt_bytes");

        SYM_CIPHER_UNIT_TEST(cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                             == 0, END, algorithm_id, "cw_sym_cipher_raw_decrypt_bytes");

        SYM_CIPHER_UNIT_TEST(plaintext_len == test_vector_len, != 1, END, algorithm_id, "Plaintext len is different from test vector len");
        SYM_CIPHER_UNIT_TEST(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, "Plaintext is different from test vector");

    END:
        if (ciphertext != NULL)
            free(ciphertext);
        if (plaintext != NULL)
            free(plaintext);
        ciphertext = NULL;
        plaintext = NULL;
    }
}

Test(Raw, CW_cipher_raw_encrypt_smaller_than_block_size)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    for (uint64_t test_vector_len = 1; test_vector_len < 15; test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            // Check if xts and wrap fails
            if (SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) || SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                             == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                             == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_decrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            ciphertext = NULL;
            plaintext = NULL;
        }
    }
}

#ifdef SYMETRIC_CIPHER_LARGER_THAN_INT_TEST
Test(Raw, CW_cipher_raw_encrypt_int_size)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    uint64_t test_vector_len = INT32_MAX;
    uint8_t *test_vector_local = NULL;

    // Use hash to minimize ram usage
    uint8_t *test_vector_hash = NULL;
    uint32_t test_vector_hash_len;

    hash_algorithm hash_algorithm_id = CW_SHA3_224;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        // Skip the following modes since they take too long
        if (algorithm_id == CW_AES_128_CFB1 ||
            algorithm_id == CW_AES_128_CFB8 ||
            algorithm_id == CW_AES_192_CFB1 ||
            algorithm_id == CW_AES_192_CFB8 ||
            algorithm_id == CW_AES_256_CFB1 ||
            algorithm_id == CW_AES_256_CFB8 ||
            algorithm_id == CW_ARIA_128_CFB1 ||
            algorithm_id == CW_ARIA_128_CFB8 ||
            algorithm_id == CW_ARIA_192_CFB1 ||
            algorithm_id == CW_ARIA_192_CFB8 ||
            algorithm_id == CW_ARIA_256_CFB1 ||
            algorithm_id == CW_ARIA_256_CFB8 ||
            algorithm_id == CW_CAMELLIA_128_CFB1 ||
            algorithm_id == CW_CAMELLIA_128_CFB8 ||
            algorithm_id == CW_CAMELLIA_192_CFB1 ||
            algorithm_id == CW_CAMELLIA_192_CFB8 ||
            algorithm_id == CW_CAMELLIA_256_CFB1 ||
            algorithm_id == CW_CAMELLIA_256_CFB8)
        {
            continue;
        }

        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_random_bytes(&test_vector_local, test_vector_len, 0),
                                         != 1, END, algorithm_id, test_vector_len, "cw_random_bytes");

        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_hash_raw_bytes(test_vector_local, test_vector_len, hash_algorithm_id, &test_vector_hash, &test_vector_hash_len, 0),
                                         != 1, END, algorithm_id, test_vector_len, "cw_hash_raw_bytes");

        uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

        uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

        // Check if xts and wrap fails
        if (SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) || SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id))
        {
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector_local, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                          != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
            goto END;
        }

        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector_local, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                         == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

        free(test_vector_local);
        test_vector_local = NULL;

        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                         == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_decrypt_bytes");

        SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_hash_verify_bytes(test_vector_hash, test_vector_hash_len, plaintext, plaintext_len, hash_algorithm_id),
                                         != 1, END, algorithm_id, test_vector_len, "Plaintext hash is different from test vector hash");

    END:
        if (ciphertext != NULL)
            free(ciphertext);
        if (plaintext != NULL)
            free(plaintext);
        if (test_vector_local != NULL)
            free(test_vector_local);
        ciphertext = NULL;
        plaintext = NULL;
        test_vector_local = NULL;
    }
}
#endif

Test(Raw, CW_cipher_raw_encrypt_bytes_no_modulo_block_size)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    for (uint64_t test_vector_len = 16; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            // Check if wrap fails
            if (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && test_vector_len % 8 != 0)
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                             == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                             == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_decrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            ciphertext = NULL;
            plaintext = NULL;
        }
    }
}

Test(Raw, CW_cipher_raw_wrong_key_size_check)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint64_t test_vector_len = 16;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
        SYM_CIPHER_UNIT_TEST(key_len, == 0, END, algorithm_id, "cw_sym_cipher_get_key_length");

        uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

        // Modify key len
        key_len += 1;

        SYM_CIPHER_UNIT_TEST_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                          != 0, END, algorithm_id, "cw_sym_cipher_raw_encrypt_bytes should have failed");

    END:
        if (ciphertext != NULL)
            free(ciphertext);
        ciphertext = NULL;
    }
}

Test(Raw, CW_cipher_raw_wrong_iv_size_check)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint64_t test_vector_len = 16;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
        SYM_CIPHER_UNIT_TEST(key_len, == 0, END, algorithm_id, "cw_sym_cipher_get_key_length");

        uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

        // Modify iv len
        iv_len += 1;

        SYM_CIPHER_UNIT_TEST_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                          != 0, END, algorithm_id, "cw_sym_cipher_raw_encrypt_bytes should have failed");

    END:
        if (ciphertext != NULL)
            free(ciphertext);
        ciphertext = NULL;
    }
}

Test(Raw, CW_cipher_raw_wrong_key_iv_max_size_check)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint64_t test_vector_len = 16;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        uint32_t key_len = UINT32_MAX;
        uint32_t iv_len = UINT32_MAX;

        SYM_CIPHER_UNIT_TEST_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                          != 0, END, algorithm_id, "cw_sym_cipher_raw_encrypt_bytes should have failed");

    END:
        if (ciphertext != NULL)
            free(ciphertext);
        ciphertext = NULL;
    }
}

Test(Raw, CW_cipher_raw_size_calculation)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    for (uint64_t test_vector_len = 16; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            uint64_t calculated_len = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);

            // Check if xts and wrap fails
            if (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && test_vector_len % 8 != 0)
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(ciphertext_len == calculated_len, != 1, END, algorithm_id, test_vector_len, "Encrypted length is different to calculated length");

        END:
            if (ciphertext != NULL)
                free(ciphertext);
            ciphertext = NULL;
        }
    }
}

Test(Raw, CW_cipher_raw_no_alloc)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;

    for (uint64_t test_vector_len = 16; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            uint64_t calculated_len = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);
            ciphertext = malloc(calculated_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((ciphertext != NULL), == 0, END, algorithm_id, test_vector_len, "Malloc failed");

            plaintext = malloc(test_vector_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((plaintext != NULL), == 0, END, algorithm_id, test_vector_len, "Malloc failed");

            if (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && test_vector_len % 8 != 0)
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector, test_vector_len, &ciphertext, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, SYMMETRIC_CIPHER_NO_ALLOC),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_decrypt_bytes(ciphertext, ciphertext_len, &plaintext, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, SYMMETRIC_CIPHER_NO_ALLOC),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_decrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");
        END:
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            ciphertext = NULL;
            plaintext = NULL;
        }
    }
}

Test(Raw, CW_cipher_raw_in_place)
{
    uint64_t ciphertext_len;

    uint64_t plaintext_len = 0;

    uint8_t *test_vector_local = NULL;

    for (uint64_t test_vector_len = 16; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint64_t calculated_len = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);

            test_vector_local = calloc(calculated_len, sizeof(uint8_t));

            memcpy(test_vector_local, test_vector, test_vector_len);

            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            if (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && test_vector_len % 8 != 0)
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_raw_encrypt_bytes(test_vector_local, test_vector_len, &test_vector_local, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, 0),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_encrypt_bytes(test_vector_local, test_vector_len, &test_vector_local, &ciphertext_len, key, key_len, iv, iv_len, algorithm_id, SYMMETRIC_CIPHER_NO_ALLOC),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_encrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_raw_decrypt_bytes(test_vector_local, ciphertext_len, &test_vector_local, &plaintext_len, key, key_len, iv, iv_len, algorithm_id, SYMMETRIC_CIPHER_NO_ALLOC),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_raw_decrypt_bytes");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector_local, test_vector, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (test_vector_local != NULL)
                free(test_vector_local);
            test_vector_local = NULL;
        }
    }
}

TestSuite(High, .description = "High Interface");

Test(High, NormalCrypt)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    SYMMETRIC_KEY_OBJECT key_obj = NULL;

    uint8_t *key = NULL;
    int key_len;

    for (uint64_t test_vector_len = 1; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            key = cw_sym_cipher_generate_symmetric_key(algorithm_id, &key_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_generate_symmetric_key");

            key_obj = cw_sym_cipher_high_generate_symmetric_object(&key, key_len, algorithm_id, 0);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key_obj != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_symmetric_object");

            if ((SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) && test_vector_len < 16) || (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && (test_vector_len % 8 != 0 || test_vector_len < 16)))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector, test_vector_len, &ciphertext, &ciphertext_len),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector, test_vector_len, &ciphertext, &ciphertext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_plain_text(key_obj, ciphertext, ciphertext_len, &plaintext, &plaintext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_plain_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (key_obj != NULL)
                cw_sym_cipher_high_delete_symmetric_key_object(key_obj);
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            if (key != NULL)
                free(key);
            ciphertext = NULL;
            plaintext = NULL;
            key_obj = NULL;
            key = NULL;
        }
    }
}

Test(High, WrongKeyObject)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    SYMMETRIC_KEY_OBJECT key_obj = NULL;
    SYMMETRIC_KEY_OBJECT key_obj_imposter = NULL;

    uint8_t *key;
    int key_len;

    uint8_t *key_imposter;
    int key_imposter_len;

    uint64_t test_vector_len = 16;

    for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
    {
        key = cw_sym_cipher_generate_symmetric_key(algorithm_id, &key_len);
        key_imposter = cw_sym_cipher_generate_symmetric_key((algorithm_id + 1) % CW_CHACHA_20, &key_imposter_len);

        SYM_CIPHER_UNIT_TEST((key != NULL), != 1, END, algorithm_id, "cw_sym_cipher_generate_symmetric_key");

        key_obj = cw_sym_cipher_high_generate_symmetric_object(&key, key_len, algorithm_id, 0);
        SYM_CIPHER_UNIT_TEST((key_obj != NULL), != 1, END, algorithm_id, "cw_sym_cipher_high_generate_symmetric_object");

        key_obj_imposter = cw_sym_cipher_high_generate_symmetric_object(&key_imposter, key_imposter_len, (algorithm_id + 1) % CW_CHACHA_20, 0);
        SYM_CIPHER_UNIT_TEST((key_obj != NULL), != 1, END, algorithm_id, "cw_sym_cipher_high_generate_symmetric_object");

        SYM_CIPHER_UNIT_TEST(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector, test_vector_len, &ciphertext, &ciphertext_len),
                             != 1, END, algorithm_id, "cw_sym_cipher_high_generate_cipher_text");

        SYM_CIPHER_UNIT_TEST_SUPPOSE_FAIL(cw_sym_cipher_high_generate_plain_text(key_obj_imposter, ciphertext, ciphertext_len, &plaintext, &plaintext_len),
                                          != 0, END, algorithm_id, "cw_sym_cipher_high_generate_plain_text should have failed");
    END:
        if (key_obj != NULL)
            cw_sym_cipher_high_delete_symmetric_key_object(key_obj);
        if (ciphertext != NULL)
            free(ciphertext);
        if (plaintext != NULL)
            free(plaintext);
        if (key != NULL)
            free(key);
        if (key_imposter != NULL)
            free(key_imposter);
        ciphertext = NULL;
        plaintext = NULL;
        key_obj = NULL;
        key = NULL;
        key_imposter = NULL;
    }
}

Test(High, NormalCryptNoKeyCopy)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len;

    SYMMETRIC_KEY_OBJECT key_obj = NULL;

    uint8_t *key = NULL;
    int key_len;

    for (uint64_t test_vector_len = 1; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            key = cw_sym_cipher_generate_symmetric_key(algorithm_id, &key_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_generate_symmetric_key");

            key_obj = cw_sym_cipher_high_generate_symmetric_object(&key, key_len, algorithm_id, SYM_CIPHER_HIGH_NO_KEY_COPY);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key_obj != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_symmetric_object");

            if ((SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) && test_vector_len < 16) || (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && (test_vector_len % 8 != 0 || test_vector_len < 16)))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector, test_vector_len, &ciphertext, &ciphertext_len),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector, test_vector_len, &ciphertext, &ciphertext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_plain_text(key_obj, ciphertext, ciphertext_len, &plaintext, &plaintext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_plain_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (key_obj != NULL)
                cw_sym_cipher_high_delete_symmetric_key_object(key_obj);
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            if (key != NULL)
                free(key);
            ciphertext = NULL;
            plaintext = NULL;
            key_obj = NULL;
            key = NULL;
        }
    }
}

Test(High, NormalCryptInPlace)
{
    uint8_t *test_vector_local = NULL;

    uint64_t ciphertext_len;

    uint64_t plaintext_len;

    SYMMETRIC_KEY_OBJECT key_obj = NULL;

    uint8_t *key = NULL;
    int key_len;

    for (uint64_t test_vector_len = 1; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint64_t calculated_len = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);

            test_vector_local = calloc(calculated_len, sizeof(uint8_t) + 100);

            memcpy(test_vector_local, test_vector, test_vector_len);

            key = cw_sym_cipher_generate_symmetric_key(algorithm_id, &key_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_generate_symmetric_key");

            key_obj = cw_sym_cipher_high_generate_symmetric_object(&key, key_len, algorithm_id, 0);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((key_obj != NULL), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_symmetric_object");

            if ((SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) && test_vector_len < 16) || (SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id) && (test_vector_len % 8 != 0 || test_vector_len < 16)))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector_local, test_vector_len, &test_vector_local, &ciphertext_len),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text should have failed");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_cipher_text(key_obj, test_vector_local, test_vector_len, &test_vector_local, &ciphertext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_cipher_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_high_generate_plain_text(key_obj, test_vector_local, ciphertext_len, &test_vector_local, &plaintext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_high_generate_plain_text");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, test_vector_local, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (key_obj != NULL)
                cw_sym_cipher_high_delete_symmetric_key_object(key_obj);
            if (key != NULL)
                free(key);
            if (test_vector_local != NULL)
                free(test_vector_local);
            key_obj = NULL;
            key = NULL;
        }
    }
}

TestSuite(Stream, .description = "Stream Interface");

Test(Stream, StreamOneCall)
{
    uint8_t *ciphertext = NULL;
    uint64_t ciphertext_len = 0;
    int ciphertext_len_temp;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;
    int plaintext_len_temp;

    CIPHER_STREAM_HANDLE encrypt_handle = NULL;
    CIPHER_STREAM_HANDLE decrypt_handle = NULL;

    for (uint64_t test_vector_len = 1; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            uint64_t cipher_size = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((cipher_size != 0), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_cipher_size");

            ciphertext = calloc(cipher_size, sizeof(uint8_t));
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((ciphertext != NULL), != 1, END, algorithm_id, test_vector_len, "calloc");

            plaintext = calloc(cipher_size, sizeof(uint8_t));
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((plaintext != NULL), != 1, END, algorithm_id, test_vector_len, "calloc");

            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            if (SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) || SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_stream_create_handle(&encrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_ENCRYPT),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_create_handle(&encrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_ENCRYPT),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(encrypt_handle, ciphertext, &ciphertext_len_temp, test_vector, test_vector_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

            ciphertext_len += ciphertext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_final(encrypt_handle, ciphertext + ciphertext_len, &ciphertext_len_temp),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_final");

            ciphertext_len += ciphertext_len_temp;




            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_create_handle(&decrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_DECRYPT),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(decrypt_handle, plaintext, &plaintext_len_temp, ciphertext, ciphertext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

            plaintext_len += plaintext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_final(decrypt_handle, plaintext + plaintext_len, &plaintext_len_temp),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_final");

            plaintext_len += plaintext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            if (encrypt_handle != NULL)
                cw_sym_cipher_stream_delete_handle(encrypt_handle);
            if (decrypt_handle != NULL)
                cw_sym_cipher_stream_delete_handle(decrypt_handle);
            ciphertext = NULL;
            plaintext = NULL;
            encrypt_handle = NULL;
            decrypt_handle = NULL;
            ciphertext_len = 0;
            plaintext_len = 0;
        }
    }
}

Test(Stream, MultipleCalls)
{
    uint8_t *ciphertext = NULL;
    uint8_t *ciphertext_copy;

    uint64_t ciphertext_len = 0;
    int ciphertext_len_temp;

    uint8_t *test_vector_copy = NULL;
    uint64_t test_vector_len_copy;

    uint8_t *plaintext = NULL;
    uint64_t plaintext_len = 0;
    int plaintext_len_temp;

    const int buffer_size = 5;

    CIPHER_STREAM_HANDLE encrypt_handle = NULL;
    CIPHER_STREAM_HANDLE decrypt_handle = NULL;

    for (uint64_t test_vector_len = 1; test_vector_len < sizeof(test_vector); test_vector_len++)
    {
        for (cw_symmetric_cipher_algorithm algorithm_id = 0; algorithm_id <= CW_CHACHA_20; algorithm_id++)
        {
            test_vector_len_copy = test_vector_len;
            test_vector_copy = test_vector;

            uint64_t cipher_size = cw_sym_cipher_get_cipher_size(algorithm_id, test_vector_len);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((cipher_size != 0), != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_cipher_size");

            ciphertext = calloc(cipher_size, sizeof(uint8_t));
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((ciphertext != NULL), != 1, END, algorithm_id, test_vector_len, "calloc");
            ciphertext_copy = ciphertext;

            plaintext = calloc(cipher_size, sizeof(uint8_t));
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE((plaintext != NULL), != 1, END, algorithm_id, test_vector_len, "calloc");

            uint32_t key_len = cw_sym_cipher_get_key_length(algorithm_id);
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(key_len, == 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_get_key_length");

            uint32_t iv_len = cw_sym_cipher_get_iv_length(algorithm_id);

            if (SYM_CIPHER_IS_XTS_INTERNAL(algorithm_id) || SYM_CIPHER_IS_WRAP_INTERNAL(algorithm_id))
            {
                SYM_CIPHER_UNIT_TEST_VECTOR_SIZE_SUPPOSE_FAIL(cw_sym_cipher_stream_create_handle(&encrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_ENCRYPT),
                                                              != 0, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");
                goto END;
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_create_handle(&encrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_ENCRYPT),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");

            if (test_vector_len > buffer_size)
            {
                do
                {
                    SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(encrypt_handle, ciphertext + ciphertext_len, &ciphertext_len_temp, test_vector_copy, buffer_size),
                                                     != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

                    test_vector_copy += buffer_size;
                    ciphertext_len += ciphertext_len_temp;
                } while ((test_vector_len_copy -= buffer_size) > buffer_size);
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(encrypt_handle, ciphertext + ciphertext_len, &ciphertext_len_temp, test_vector_copy, (int)test_vector_len_copy),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

            ciphertext_len += ciphertext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_final(encrypt_handle, ciphertext + ciphertext_len, &ciphertext_len_temp),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_final");

            ciphertext_len += ciphertext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_create_handle(&decrypt_handle, algorithm_id, key, key_len, iv, iv_len, SYMMETRIC_CIPHER_DECRYPT),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_create_handle");

            if (ciphertext_len > buffer_size)
            {
                do
                {
                    SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(decrypt_handle, plaintext + plaintext_len, &plaintext_len_temp, ciphertext_copy, buffer_size),
                                                     != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

                    ciphertext_copy += buffer_size;
                    plaintext_len += plaintext_len_temp;
                } while ((ciphertext_len -= buffer_size) > buffer_size);
            }

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_update(decrypt_handle, plaintext + plaintext_len, &plaintext_len_temp, ciphertext_copy, (int)ciphertext_len),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_update");

            plaintext_len += plaintext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(cw_sym_cipher_stream_final(decrypt_handle, plaintext + plaintext_len, &plaintext_len_temp),
                                             != 1, END, algorithm_id, test_vector_len, "cw_sym_cipher_stream_final");

            plaintext_len += plaintext_len_temp;

            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(plaintext_len == test_vector_len, != 1, END, algorithm_id, test_vector_len, "Plaintext len is different from test vector len");
            SYM_CIPHER_UNIT_TEST_VECTOR_SIZE(memcmp(test_vector, plaintext, plaintext_len), != 0, END, algorithm_id, test_vector_len, "Plaintext is different from test vector");

        END:
            if (ciphertext != NULL)
                free(ciphertext);
            if (plaintext != NULL)
                free(plaintext);
            if (encrypt_handle != NULL)
                cw_sym_cipher_stream_delete_handle(encrypt_handle);
            if (decrypt_handle != NULL)
                cw_sym_cipher_stream_delete_handle(decrypt_handle);
            ciphertext = NULL;
            plaintext = NULL;
            encrypt_handle = NULL;
            decrypt_handle = NULL;
            ciphertext_len = 0;
            plaintext_len = 0;
        }
    }
}
