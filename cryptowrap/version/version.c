/*
 * Copyright (c) 2022 Leon Weinmann
 *
 * Licensed under the MIT License. You may not use
 * this file except in compliance with the License. You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

#include "cryptowrap/version.h"

#include <openssl/evp.h>
#include <stdio.h>

#define CRYPTO_WRAP_VERSION_STR "1.0.0"

void cw_print_version()
{
    printf("Crypto Wrap Version: " CRYPTO_WRAP_VERSION_STR "\n");

    // Dummy call to openssl 3.x function to check if linking works
    EVP_CIPHER_fetch(NULL, NULL, NULL);
}