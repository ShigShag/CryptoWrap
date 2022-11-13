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

#include <cryptowrap/hash.h>
#include <cryptowrap/error.h>
#include <internal/fetching.h>

/* TEST VECTORS */
const char *in_str = "nuch3ii5xoYaing2geedoothiushohx1raitaik1aM4Boo9ahr";
uint8_t in_bytes[] = "nuch3ii5xoYaing2geedoothiushohx1raitaik1aM4Boo9ahr";
uint8_t hashes[][64] = {
    // md5
    {0x2f, 0x16, 0x78, 0x84, 0x93, 0x30, 0xfc, 0xd1, 0x23, 0xad, 0xb8, 0x05, 0x5e, 0xde, 0xda, 0xca},

    // sha1
    {0xe4, 0x14, 0x0f, 0xd7, 0x6a, 0xa8, 0x01, 0xaf, 0xb9, 0x19, 0x1b, 0xdc, 0x90, 0x34, 0x47, 0x30, 0x9a, 0x2f, 0xeb, 0x22},

    // sha224
    {0x94, 0xbc, 0x46, 0x7f, 0xe1, 0x34, 0x72, 0xfc, 0xbd, 0x8d, 0xb5, 0xcf, 0x49, 0x37, 0xc7, 0xb4, 0xbf, 0x16, 0xf2, 0x1a,
     0x45, 0x3e, 0x38, 0xca, 0x8c, 0x46, 0x47, 0xac},

    // sha_256
    {0x23, 0x70, 0xc6, 0x1a, 0xb6, 0xd1, 0x9d, 0xa3, 0x35, 0x13, 0x12, 0x4c, 0xcb, 0x8b, 0x21, 0x07, 0xfe, 0x9d, 0x31, 0xa1, 0xfb,
     0x78, 0xf3, 0x4e, 0xc2, 0xe4, 0x3d, 0x5e, 0x7f, 0x2f, 0xca, 0x3f},

    // sha_384
    {0x52, 0x23, 0xb0, 0x03, 0x96, 0xe6, 0xcb, 0x6c, 0xcb, 0x46, 0x35, 0xec, 0x7f, 0xdf, 0xe6, 0xab, 0x10, 0x33, 0xb8, 0xc6, 0xcc,
     0x79, 0x1e, 0x4b, 0x91, 0xde, 0x22, 0xfc, 0x45, 0xa7, 0xad, 0x95, 0x38, 0x5d, 0x3c, 0xf2, 0x29, 0x41, 0xe3, 0x2a, 0x58, 0xd9,
     0xeb, 0x86, 0x13, 0x00, 0x8a, 0xe8},

    // sha512
    {0x60, 0xe9, 0x89, 0xce, 0x9d, 0x57, 0x16, 0x12, 0x30, 0x38, 0x72, 0x2d, 0x01, 0xdf, 0x56, 0x97, 0x67, 0xdc, 0xd2, 0xc4, 0xa4,
     0x84, 0x21, 0x89, 0xa4, 0x32, 0xb8, 0xf3, 0x99, 0xc8, 0x51, 0x41, 0x86, 0x35, 0xd7, 0xf0, 0x49, 0x53, 0x3c, 0x21, 0xc8, 0x36, 0x38,
     0x4d, 0xb1, 0x22, 0x41, 0xab, 0x02, 0x86, 0xe2, 0x66, 0xc0, 0xa0, 0x5d, 0x9d, 0xea, 0x26, 0xb7, 0xed, 0xea, 0x9d, 0x09, 0x8e},

    // sha512_224
    {0x82, 0xbe, 0x70, 0x8f, 0xec, 0xce, 0x4c, 0x6b, 0x17, 0xbf, 0xf4, 0x16, 0x11, 0x66, 0x74, 0xb6, 0xf5, 0x55, 0xcd, 0x85, 0xb2, 0xe6,
     0x08, 0xbd, 0x0e, 0x75, 0xe1, 0xb2},

    // sha_512_256
    {0xc5, 0x8c, 0xb9, 0xdf, 0xf7, 0x07, 0x91, 0x63, 0xbd, 0xd3, 0x56, 0xce, 0xf1, 0x13, 0xed, 0xa3, 0x4b, 0x3a, 0xef, 0x8e, 0x15, 0x96,
     0x93, 0x30, 0x17, 0xce, 0x05, 0xab, 0x16, 0xaa, 0xdc, 0x39},

    // sha3_224
    {0x7c, 0x0d, 0x8f, 0x9c, 0xe9, 0x4e, 0xb8, 0x59, 0xe7, 0xf2, 0x2b, 0x6d, 0xf9, 0x15, 0xf6, 0x4f, 0xae, 0xe8, 0xb9, 0x5d, 0xd9, 0x1a,
     0xe2, 0xb1, 0x41, 0xb4, 0x3c, 0x8c},

    // sha3_256
    {0xb1, 0x78, 0x8b, 0x2a, 0xfb, 0xdb, 0xeb, 0x80, 0x00, 0x31, 0x42, 0xcb, 0x35, 0x83, 0x6e, 0xba, 0x1a, 0xec, 0x86, 0x48, 0x51, 0xea,
     0xcb, 0xcd, 0x08, 0x46, 0x94, 0xd1, 0x21, 0x3f, 0xf7, 0xc7},

    // sha3_384
    {0xb4, 0xd9, 0x65, 0x69, 0xab, 0xc3, 0x26, 0xe7, 0x02, 0xe6, 0x7c, 0xd4, 0xd1, 0x1f, 0x4a, 0x3b, 0xcd, 0xe0, 0x1e, 0x57, 0xce, 0x87,
     0x85, 0x84, 0x5e, 0x90, 0x89, 0xb3, 0x5e, 0xb7, 0x82, 0xd8, 0x3e, 0x22, 0x89, 0xb7, 0xfe, 0xec, 0x55, 0x38, 0x5c, 0xa3, 0xeb, 0x27, 0x2c,
     0x98, 0x21, 0x2c},

    // sha3_512
    {0xcb, 0x91, 0x4a, 0xc2, 0x80, 0xc2, 0xe3, 0x0a, 0xae, 0xfc, 0xd7, 0xba, 0x21, 0xee, 0x31, 0x69, 0x0b, 0x8e, 0xac, 0x43, 0x02, 0xe5, 0xe4,
     0x81, 0xac, 0x87, 0xc2, 0xee, 0xef, 0x61, 0x93, 0x5d, 0x8d, 0x83, 0xab, 0x8f, 0x21, 0x04, 0x7b, 0xf7, 0x83, 0x6e, 0x13, 0x9f, 0x17, 0x2e, 0x69,
     0x9b, 0xf6, 0x54, 0x63, 0xf9, 0x51, 0xa8, 0x28, 0x8c, 0x5e, 0xd0, 0xaa, 0x9b, 0xea, 0x6e, 0xe2, 0xe0},

    // shake_128
    {0xd1, 0x0b, 0x0d, 0x2f, 0xd8, 0x4b, 0xc2, 0x72, 0x6c, 0x98, 0x8b, 0xb5, 0xab, 0x79, 0xed, 0xe6},

    // shake_256
    {0x6b, 0x5f, 0xeb, 0x97, 0x46, 0x72, 0x51, 0x1a, 0xe7, 0x2e, 0x25, 0x4b, 0x24, 0xbe, 0x75, 0x18, 0x9e, 0x4b, 0x41, 0x00, 0x05, 0xe7, 0xb8, 0xc9, 0x29,
     0xd6, 0xf7, 0x59, 0x28, 0x57, 0x00, 0xf3},

    // sm_3
    {0xa8, 0x70, 0xbd, 0x68, 0x63, 0xef, 0xc8, 0xb6, 0x2b, 0x58, 0x6b, 0x3f, 0x65, 0x87, 0xcf, 0x7e, 0x79, 0x00, 0xe3, 0x4b, 0xa3, 0x8e, 0x55, 0x77, 0xcf, 0x70,
     0x4c, 0xd9, 0x00, 0x58, 0xae, 0x3a},

    // md_4
    {0x03, 0x74, 0xd4, 0xd6, 0x1e, 0xec, 0xae, 0x37, 0xca, 0xc2, 0xd4, 0x9a, 0xad, 0x71, 0x6f, 0x04},

    // whirlpool
    {0x5c, 0xd8, 0x43, 0xa8, 0xc8, 0x9d, 0x7a, 0x3d, 0xe5, 0x5e, 0x53, 0xaf, 0xa3, 0xd8, 0x73, 0xac, 0x39, 0x6f, 0x32, 0xc1, 0xd5, 0x51, 0x1c, 0x36, 0xdf,
     0x88, 0x04, 0xd0, 0x16, 0x01, 0x74, 0xb8, 0x69, 0x9c, 0x00, 0x67, 0x67, 0xc7, 0xfd, 0x0b, 0xe5, 0x4e, 0xe6, 0xb2, 0xcc, 0x3c, 0x70, 0x73, 0xf8, 0x7a, 0xcc,
     0x1f, 0x33, 0xa5, 0x69, 0x49, 0xcd, 0x7f, 0x5f, 0x13, 0xfb, 0x1b, 0xc6, 0x68},

    // ripemd_160
    {0x86, 0xe5, 0xa4, 0xec, 0x6c, 0x1f, 0xdb, 0x39, 0xca, 0x61, 0x23, 0x69, 0xe6, 0xa3, 0xa7, 0xce, 0xd9, 0xdb, 0x5e, 0x4b},

    //  blake 2s 256
    {0x13, 0xc1, 0x51, 0x25, 0x4e, 0x9c, 0x4a, 0x4a, 0x50, 0x71, 0x33, 0xc5, 0xb2, 0x04, 0x10, 0x49, 0xb2, 0x77, 0x71, 0x53, 0x5c,
     0xde, 0x91, 0x9b, 0x98, 0x43, 0x32, 0x4f, 0x3d, 0xd3, 0x61, 0x3d},

    //  blake 2b 512
    {0xc4, 0x83, 0xc8, 0xb0, 0xe9, 0xc5, 0xe5, 0x8a, 0xf2, 0xd2, 0xf0, 0x8d, 0xb1, 0xdc, 0x16, 0x75, 0xd9, 0x5a, 0x31, 0xf2, 0xa7,
     0x88, 0xf1, 0xca, 0xc7, 0xd0, 0xd8, 0x40, 0x28, 0x0c, 0x21, 0xeb, 0xd7, 0x9c, 0xdf, 0x7d, 0x5c, 0xe7, 0x88, 0xf8, 0xf5, 0x6b, 0x92,
     0x63, 0xa6, 0x10, 0xd6, 0xed, 0x14, 0x6c, 0xd5, 0xc8, 0x84, 0xa1, 0x30, 0x7f, 0x31, 0x98, 0x21, 0x93, 0x99, 0x90, 0x72, 0xf9}};

/* TEST VECTORS */

#define CR_CW_HASH_EXPECT(func_call, fail_value, fail_msg, hash_algortihm_id, end_point)                                        \
    do                                                                                                                          \
    {                                                                                                                           \
        char *__local_msg__ = NULL;                                                                                             \
        int __local_ret__ = func_call;                                                                                          \
        if (__local_ret__ fail_value)                                                                                           \
        {                                                                                                                       \
            __local_msg__ = cw_error_get_last_error_str_ex(NULL);                                                               \
            cr_expect(0, "%s\nHash algorithm: %s\n%s", fail_msg, cw_fetch_hash_str_internal(hash_algortihm_id), __local_msg__); \
            free(__local_msg__);                                                                                                \
            goto end_point;                                                                                                     \
        }                                                                                                                       \
    } while (0)

/* Testing */
TestSuite(Raw, .description = "Raw Interface");

Test(Raw, hash_bytes)
{
    uint8_t *out = NULL;
    uint32_t out_len;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        out = NULL;

        CR_CW_HASH_EXPECT(cw_hash_raw_bytes(in_bytes, sizeof(in_bytes) - 1, algorithm_id, &out, &out_len, 0), != 1, "cw_hash_raw_bytes failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(memcmp(hashes[algorithm_id], out, out_len), != 0, "memcmp => produced hash not equal to test vector hash", algorithm_id, END);
    END:
        if (out != NULL)
            free(out);
    }
}

Test(Raw, hash_string)
{
    uint8_t *out = NULL;
    uint32_t out_len;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_raw_string(in_str, algorithm_id, &out, &out_len, 0), != 1, "cw_hash_raw_string failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(memcmp(hashes[algorithm_id], out, out_len), != 0, "memcmp => produced hash not equal to test vector hash", algorithm_id, END);
    END:
        if (out != NULL)
            free(out);
        out = NULL;
    }
}

Test(Raw, hash_bytes_no_alloc)
{
    uint8_t *out = NULL;
    uint32_t out_len;
    hash_algorithm algorithm_id;

    for (algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        out = NULL;
        out_len = cw_hash_get_len(algorithm_id);

        CR_CW_HASH_EXPECT(out_len, == 0, "cw_hash_get_len failed", algorithm_id, END);
        out = malloc(out_len);
        CR_CW_HASH_EXPECT((out == NULL) ? 0 : 1, == 0, "Malloc failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_raw_bytes(in_bytes, sizeof(in_bytes) - 1, algorithm_id, &out, &out_len, HASH_NO_ALLOC), != 1, "cw_hash_raw_bytes failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(memcmp(hashes[algorithm_id], out, out_len), != 0, "memcmp => produced hash not equal to test vector hash", algorithm_id, END);

    END:
        if (out != NULL)
            free(out);
    }
}

Test(Raw, hash_string_no_alloc)
{
    uint8_t *out = NULL;
    uint32_t out_len;
    hash_algorithm algorithm_id;

    for (algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        out = NULL;
        out_len = cw_hash_get_len(algorithm_id);

        CR_CW_HASH_EXPECT(out_len, == 0, "cw_hash_get_len failed", algorithm_id, END);
        out = malloc(out_len);
        CR_CW_HASH_EXPECT((out == NULL) ? 0 : 1, == 0, "Malloc failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_raw_string(in_str, algorithm_id, &out, &out_len, HASH_NO_ALLOC), != 1, "cw_hash_raw_string failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(memcmp(hashes[algorithm_id], out, out_len), != 0, "memcmp => produced hash not equal to test vector hash", algorithm_id, END);

    END:
        if (out != NULL)
            free(out);
    }
}

TestSuite(Verification, .description = "Verification");

Test(Verification, verify_bytes)
{
    uint8_t *out = NULL;
    uint32_t out_len = 0;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_raw_bytes(in_bytes, sizeof(in_bytes) - 1, algorithm_id, &out, &out_len, 0), != 1, "cw_hash_raw_bytes failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_verify_bytes(out, out_len, in_bytes, sizeof(in_bytes) - 1, algorithm_id), != 1, "cw_hash_verify_bytes failed", algorithm_id, END);
    END:
        if (out != NULL)
            free(out);
        out = NULL;
    }
}

Test(Verification, verify_string)
{
    uint8_t *out = NULL;
    uint32_t out_len = 0;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_raw_string(in_str, algorithm_id, &out, &out_len, 0), != 1, "cw_hash_raw_string failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_verify_string(out, out_len, in_str, algorithm_id), != 1, "cw_hash_verify_string failed", algorithm_id, END);
    END:
        if (out != NULL)
            free(out);
        out = NULL;
    }
}

TestSuite(Stream, .description = "Stream");

Test(Stream, hash_stream_one_call)
{
    HASH_STREAM_HANDLE stream_handle = NULL;

    uint8_t *out = NULL;
    uint32_t out_len = 0;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_stream_create_handle(&stream_handle, algorithm_id), != 1, "cw_hash_stream_create_handle failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_stream_update(stream_handle, in_bytes, sizeof(in_bytes) - 1), != 1, "cw_hash_stream_update failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_stream_finalize(stream_handle, &out, &out_len, 0), != 1, "cw_hash_stream_finalize failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_verify_bytes(out, out_len, in_bytes, sizeof(in_bytes) - 1, algorithm_id), != 1, "cw_hash_verify_bytes failed", algorithm_id, END);

    END:
        if (out != NULL)
            free(out);
        if (stream_handle != NULL)
            cw_hash_stream_delete_handle(stream_handle);

        stream_handle = NULL;
        out = NULL;
    }
}

Test(Stream, hash_stream_multiple_call)
{
    HASH_STREAM_HANDLE stream_handle = NULL;

    uint8_t *out = NULL;
    uint32_t out_len = 0;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_stream_create_handle(&stream_handle, algorithm_id), != 1, "cw_hash_stream_create_handle failed", algorithm_id, END);

        for (uint32_t i = 0; i < sizeof(in_bytes) - 1; i++)
        {
            CR_CW_HASH_EXPECT(cw_hash_stream_update(stream_handle, in_bytes + i, 1), != 1, "cw_hash_stream_update failed", algorithm_id, END);
        }
        CR_CW_HASH_EXPECT(cw_hash_stream_finalize(stream_handle, &out, &out_len, 0), != 1, "cw_hash_stream_finalize failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_verify_bytes(out, out_len, in_bytes, sizeof(in_bytes) - 1, algorithm_id), != 1, "cw_hash_verify_bytes failed", algorithm_id, END);

    END:
        if (out != NULL)
            free(out);
        if (stream_handle != NULL)
            cw_hash_stream_delete_handle(stream_handle);

        stream_handle = NULL;
        out = NULL;
    }
}

Test(Stream, hash_stream_multiple_call_no_alloc)
{
    HASH_STREAM_HANDLE stream_handle = NULL;

    uint8_t *out = NULL;
    uint32_t out_len = 0;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        out_len = cw_hash_get_len(algorithm_id);
        CR_CW_HASH_EXPECT(out_len, == 0, "cw_hash_get_len failed", algorithm_id, END);
        out = malloc(out_len);
        CR_CW_HASH_EXPECT((out == NULL) ? 0 : 1, == 0, "Malloc failed", algorithm_id, END);

        CR_CW_HASH_EXPECT(cw_hash_stream_create_handle(&stream_handle, algorithm_id), != 1, "cw_hash_stream_create_handle failed", algorithm_id, END);

        for (uint32_t i = 0; i < sizeof(in_bytes) - 1; i++)
        {
            CR_CW_HASH_EXPECT(cw_hash_stream_update(stream_handle, in_bytes + i, 1), != 1, "cw_hash_stream_update failed", algorithm_id, END);
        }
        CR_CW_HASH_EXPECT(cw_hash_stream_finalize(stream_handle, &out, &out_len, HASH_NO_ALLOC), != 1, "cw_hash_stream_finalize failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_verify_bytes(out, out_len, in_bytes, sizeof(in_bytes) - 1, algorithm_id), != 1, "cw_hash_verify_bytes failed", algorithm_id, END);

    END:
        if (out != NULL)
            free(out);
        if (stream_handle != NULL)
            cw_hash_stream_delete_handle(stream_handle);

        stream_handle = NULL;
        out = NULL;
    }
}

Test(Stream, hash_stream_fail)
{
    HASH_STREAM_HANDLE stream_handle = NULL;

    uint8_t *out = NULL;

    for (hash_algorithm algorithm_id = 0; algorithm_id <= CW_BLAKE2B_512; algorithm_id++)
    {
        CR_CW_HASH_EXPECT(cw_hash_stream_create_handle(&stream_handle, algorithm_id), != 1, "cw_hash_stream_create_handle failed", algorithm_id, END);
        CR_CW_HASH_EXPECT(cw_hash_stream_update(stream_handle, out, 0), != 0, "cw_hash_stream_update should have fail failed", algorithm_id, END);
    }
END:
    if (out != NULL)
        free(out);
    if (stream_handle != NULL)
        cw_hash_stream_delete_handle(stream_handle);

    stream_handle = NULL;
    out = NULL;
}
