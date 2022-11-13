/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include <cryptowrap/ecc.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

// Try not. Do or do not. There is no try
uint8_t message[38] = {
    0x54, 0x72, 0x79, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x44, 0x6F, 0x20,
    0x6F, 0x72, 0x20, 0x64, 0x6F, 0x20, 0x6E, 0x6F, 0x74, 0x2E, 0x20, 0x54,
    0x68, 0x65, 0x72, 0x65, 0x20, 0x69, 0x73, 0x20, 0x6E, 0x6F, 0x20, 0x74,
    0x72, 0x79};

void sign_and_verify()
{
    ECC_KEY_PAIR key_pair = NULL;

    uint8_t *signature = NULL;
    uint64_t signature_len = 0;

    // Create the key pair
    if (cw_ecc_generate_key_pair(&key_pair, CW_NIST_P_512) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Create the signature with SHA 512
    if (cw_ecc_sign_bytes(key_pair, message, sizeof(message), CW_ECC_SIG_HASH_SHA512, &signature, &signature_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the signature
    printf("Signature:\n");
    BIO_dump_fp(stdout, signature, signature_len);

    // Verify the signature
    if (cw_ecc_verify_bytes(key_pair, message, sizeof(message), signature, signature_len, CW_ECC_SIG_HASH_SHA512) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nVerification successful\n");

END:
    if (key_pair != NULL)
        cw_ecc_delete_key_pair(key_pair);
    if (signature != NULL)
        free(signature);
}

int main()
{
    sign_and_verify();

    return EXIT_SUCCESS;
}