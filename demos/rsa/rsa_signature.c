/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/rsa.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// Try not. Do or do not. There is no try
uint8_t message[38] = {
    0x54, 0x72, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x44, 0x6F, 0x20,
    0x6F, 0x72, 0x20, 0x64, 0x6F, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x54,
    0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x20, 0x74,
    0x72, 0x79};

void sign_verify_message()
{
    CW_RSA_KEY_PAIR key_pair = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    // Generate a key pair which is 1024 bit strong
    if (cw_rsa_generate_key_pair(&key_pair, 1024) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Sign the message with SHA 3 256 and PSS padding.
    if (cw_rsa_sign_bytes(key_pair, message, sizeof(message), CW_RSA_SIG_HASH_SHA3_256, CW_RSA_PKCS1_PSS_PADDING,
                          &signature, &signature_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the signature
    printf("Message signature:\n");
    BIO_dump_fp(stdout, signature, signature_len);

    // Verify the signature against the message
    if (cw_rsa_verify_bytes(key_pair, message, sizeof(message), signature, signature_len,
                            CW_RSA_SIG_HASH_SHA3_256, CW_RSA_PKCS1_PSS_PADDING) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nVerification was successful\n");

END:
    if (key_pair != NULL)
        cw_rsa_delete_key_pair(key_pair);
    if (signature != NULL)
        free(signature);
}

int main()
{
    sign_verify_message();

    return EXIT_SUCCESS;
}