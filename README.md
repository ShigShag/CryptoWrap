# CryptoWrap

CryptoWrap is a wrapper library for **cryptographic algorithms**. It compresses mainly [OpenSSL](https://github.com/openssl/openssl) routines into easy to use functions, making them more accessible. The intention of this library is to save time when developing applications which require cryptographic features. It is dedicated towards lower experienced users but may also be used by skilled individuals, to either use the algorithm accessible in this library or to familiarize themselves with the OpenSSL library.

# Table of Contents

 - [Overview](#overview)
 - [Examples](#examples)
 - [Requirements](#requirements)
 - [Installation](#installation)
 - [Documentation](#documentation)
 - [License](#license)

# Overview

Build in cryptographic features are:

* **Authenticated Encryption and Decryption**
    * GCM, CCM, OCB, POLY 1305
* **Elliptic curve cryptography**
    * Key generation, serialization and signature / verification
* **Hashing**
    * SHA, SHAKE, SM3, MD4/5, WHIRLPOOL, RIPEMD_160, BLAKE2S_256, BLAKE2B_512
* **Key derivation**
    * PBKDF2, HKDF, SCRYPT, [Argon2](https://github.com/P-H-C/phc-winner-argon2)
* **Key exchange**
    * Elliptic-curve Diffie–Hellman, X448, X22519
* **Message authentication codes**
    * HMAC, CMAC, GMAC, KMAC, SIPHASH
* **Random number generation**
    * Random bytes / numbers
* **Rsa**
    * Key generation, serialization, signature / verification and encryption / decryption
* **Symmetric cipher**
    * AES, ARIA, CAMELLIA, ChaCha20
* **Base64**
    * Encoding / Decoding

As mentioned before, the algorithms are implemented by [OpenSSL](https://github.com/openssl/openssl). Expect for Argon2 which is implemented through [the official Argon2 repository](https://github.com/P-H-C/phc-winner-argon2).

# Examples

#### Hashing a string:

```c
#include <cryptowrap/hash.h>
#include <cryptowrap/error.h>
#include <stdlib.h>

int main()
{
    const char *string = "Hello, World!";

    uint8_t *hash;
    uint32_t hash_len;

    if (cw_hash_raw_string(string, CW_SHA_256, &hash, &hash_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return EXIT_FAILURE;
    }

    for (uint32_t i = 0; i < hash_len; i++)
    {
        printf("%02x", hash[i]);
    }

    free(hash);

    return EXIT_SUCCESS;
}
```

#### Encrypting data with AES:
 
```c
#include <cryptowrap/symmetric_cipher.h>
#include <cryptowrap/error.h>

#include <stdlib.h>
#include <string.h>

int main()
{
    char *string = "Secret message";

    // Dont use hardcoded keys ;)
    uint8_t secret_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};

    uint8_t iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};

    uint8_t *encrypted_string = NULL;
    uint64_t encrypted_string_len = 0;

    if (cw_sym_cipher_raw_encrypt_bytes((uint8_t *)string, strlen(string),
                                        &encrypted_string, &encrypted_string_len,
                                        secret_key, sizeof(secret_key),
                                        iv, sizeof(iv),
                                        CW_AES_128_CTR, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        return EXIT_FAILURE;
    }

    for (uint32_t i = 0; i < encrypted_string_len; i++)
    {
        printf("%02x", encrypted_string[i]);
    }

    free(encrypted_string);

    return EXIT_SUCCESS;
}
```

For more examples **make sure** to review the [demos folder](demos/).

# Requirements

The library was developed **for Linux systems**.

Prerequisites to compile and run the library:

* At least [OpenSSL](https://github.com/openssl/openssl) Version 3.0

For testing purposes only:

* [Criterion](https://github.com/Snaipe/Criterion)

Argon2 is included within the source code.

# Installation

You can compile a **static** or **shared** library.

### **static:**

```
make
```

or

```
make static
```

___

Result will be a static library file named *libcwrap.a*. In order to compile a program use the following command:

```sh
gcc main.c libcwrap.a -lcrypto
```

___

Run tests:

```
make test
```

or

```
make static_test
```

___

### **shared:**

```
make shared
```

or

```
make install
```

___

Both versions will create a file named *libcwrap.so*. The *install* version will try to copy the library file into */usr/lib* and the header files into */usr/include*. For this operations root rights are necessary.

To compile a program use the following command:

```
gcc main.c -lcwrap -lcrypto
```

___

Run tests:

```
make shared_test
```

___

**Make sure to link CryptoWrap before OpenSSL when using both static or shared libraries.**  
**When compiling a different library make sure to clean the old objective files.**

Header files **to be used** for cryptographic operations are located at [include/cryptowrap](include/cryptowrap). Header files located at [include/internal](include/internal) are dedicated for internal usage.

# Documentation

To create a [Doxygen](https://github.com/doxygen/doxygen) documentation use the [Doxyfile](docs/Doxyfile). Furthermore the [demos folder](demos/) can be reviewed for proper usage.

# License

CryptoWrap is licensed under the *MIT-License*. Review the [*LICENSE*](LICENSE) for more details.

OpenSSL is included under the *Apache License 2.0*, thus an associated license file can be reviewed at [*LICENSE.APACHE_20*](LICENSE.APACHE_20).
