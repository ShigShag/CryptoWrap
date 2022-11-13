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

void generate_rsa_key_write_private()
{
    // Variable to save the key pair
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_load = NULL;

    const char *file_path = "priv.key";

    // Generate a key pair which is 2048 bit strong
    if (cw_rsa_generate_key_pair(&key_pair, 2048) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Save the key_pair in a file
    if (cw_rsa_write_private_key(file_path, key_pair, NULL, CW_RSA_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the key pair within the file
    printf("\nWritten key pair:\n");
    helper_print_file_contents(file_path);

    // Load the private key from the file
    if (cw_rsa_load_private_key(file_path, &key_pair_load, NULL, CW_RSA_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nLoaded key pair:\n");

    // Write loaded private key via OpenSSL function
    PEM_write_PrivateKey(stdout, key_pair_load, NULL, NULL, 0, NULL, NULL);

END:
    // Delete key pair
    if (key_pair != NULL)
        cw_rsa_delete_key_pair(key_pair);

    if (key_pair_load != NULL)
        cw_rsa_delete_key_pair(key_pair_load);
}

void generate_rsa_key_write_public()
{
    // Variable to save the key pair
    CW_RSA_KEY_PAIR key_pair = NULL;
    CW_RSA_KEY_PAIR key_pair_load = NULL;

    const char *file_path = "pub.key";

    // Generate a key pair which is 2048 bit strong
    if (cw_rsa_generate_key_pair(&key_pair, 2048) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Save the key_pair in a file
    if (cw_rsa_write_public_key(file_path, key_pair, CW_RSA_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Print the key pair within the file
    printf("\nWritten public key:\n");
    helper_print_file_contents(file_path);

    // Load the private key from the file
    if (cw_rsa_load_public_key(file_path, &key_pair_load, CW_RSA_PEM) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    printf("\nLoaded public key:\n");

    // Write loaded public key via OpenSSL function
    PEM_write_PUBKEY(stdout, key_pair_load);

END:
    // Delete key pair
    cw_rsa_delete_key_pair(key_pair);
}

int main()
{
    generate_rsa_key_write_private();

    generate_rsa_key_write_public();

    return EXIT_SUCCESS;
}