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

void helper_print_file_contents(const char *file_path)
{
    FILE *fp = NULL;
    uint8_t buf[20] = {0};
    size_t bytes_read = 0;

    if ((fp = fopen(file_path, "rb")) == NULL)
        return;

    while ((bytes_read = fread(buf, sizeof(uint8_t), sizeof(buf), fp)) > 0)
    {
        fwrite(buf, sizeof(uint8_t), bytes_read, stdout);
    }

    fclose(fp);
}

void generate_key_pair_write_private()
{
    ECC_KEY_PAIR key_pair = NULL;
    ECC_KEY_PAIR key_pair_load = NULL;

    const char *file_path = "priv.key";

    // Generate a key pair based on NIST P 512 curve
    if (cw_ecc_generate_key_pair(&key_pair, CW_NIST_P_512) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Write the key pair into a file
    if (cw_ecc_write_private_key(file_path, key_pair, NULL, CW_ECC_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Display file contents
    printf("\nWritten key pair:\n");
    helper_print_file_contents(file_path);

    if (cw_ecc_load_private_key(file_path, &key_pair_load, NULL, CW_ECC_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nLoaded key pair:\n");

    // Write loaded private key via OpenSSL function
    PEM_write_PrivateKey(stdout, key_pair_load, NULL, NULL, 0, NULL, NULL);

END:
    if (key_pair != NULL)
        cw_ecc_delete_key_pair(key_pair);

    if (key_pair_load != NULL)
        cw_ecc_delete_key_pair(key_pair_load);
}

void generate_key_pair_write_public()
{
    ECC_KEY_PAIR key_pair = NULL;
    ECC_KEY_PAIR key_pair_load = NULL;

    const char *file_path = "pub.key";

    // Generate a key pair based on NIST P 512 curve
    if (cw_ecc_generate_key_pair(&key_pair, CW_NIST_P_512) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Write the key pair into a file
    if (cw_ecc_write_public_key(file_path, key_pair, CW_ECC_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Display file contents
    printf("\nWritten public key:\n");
    helper_print_file_contents(file_path);

    if (cw_ecc_load_public_key(file_path, &key_pair_load, CW_ECC_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nLoaded public key:\n");

    // Write loaded private key via OpenSSL function
    PEM_write_PUBKEY(stdout, key_pair_load);

END:
    if (key_pair != NULL)
        cw_ecc_delete_key_pair(key_pair);

    if (key_pair_load != NULL)
        cw_ecc_delete_key_pair(key_pair_load);
}

int main()
{
    generate_key_pair_write_private();

    generate_key_pair_write_public();

    return EXIT_SUCCESS;
}