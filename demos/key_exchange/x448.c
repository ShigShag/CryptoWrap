#include <cryptowrap/key_exchange.h>
#include <cryptowrap/error.h>

#include <openssl/bio.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int x448_key_exchange()
{
    PEER_DATA alice = NULL;
    PEER_DATA bob = NULL;

    uint8_t *alice_pub_key = NULL;
    uint32_t alice_pub_key_len;

    uint8_t *bob_pub_key = NULL;
    uint32_t bob_pub_key_len;

    uint8_t *alice_secret = NULL;
    uint64_t alice_secret_len;

    uint8_t *bob_secret = NULL;
    uint64_t bob_secret_len;

    // Create Alices key
    if (cw_keyexch_x448_init(&alice, NULL, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Create Bobs key
    if (cw_keyexch_x448_init(&bob, NULL, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Get Alices public key and save it in byte form
    if (cw_keyexch_peer_get_pub_key(alice, &alice_pub_key, &alice_pub_key_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Get Bobs public key and save it in byte form
    if (cw_keyexch_peer_get_pub_key(bob, &bob_pub_key, &bob_pub_key_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // At this point both keys need to be distributed to the other person

    // Derive key based on Alice´s private and Bob´s public key
    if (cw_keyexch_x448_derive(alice, bob_pub_key, bob_pub_key_len, &alice_secret, &alice_secret_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    // Derive key based on Bob´s private and Alice´s public key
    if (cw_keyexch_x448_derive(bob, alice_pub_key, alice_pub_key_len, &bob_secret, &bob_secret_len, 0) != 1)
    {
        cw_error_get_last_error_fp_ex(stdout);
        goto END;
    }

    if (bob_secret_len != alice_secret_len)
    {
        printf("Secret lengths are not equal\n");
        goto END;
    }

    if (CRYPTO_memcmp(alice_secret, bob_secret, bob_secret_len) != 0)
    {
        printf("Alice and bob secrets are not equal\n");
        goto END;
    }

    printf("Secrets are equal\n\n");

    // Print the secrets
    printf("Alice secret:\n");
    BIO_dump_fp(stdout, alice_secret, alice_secret_len);

    printf("\nBob secret:\n");
    BIO_dump_fp(stdout, bob_secret, bob_secret_len);

END:
    if (alice != NULL)
        cw_keyexch_peer_data_delete(alice);
    if (bob != NULL)
        cw_keyexch_peer_data_delete(bob);
    if (alice_pub_key != NULL)
        free(alice_pub_key);
    if (bob_pub_key != NULL)
        free(bob_pub_key);
    if (alice_secret != NULL)
        free(alice_secret);
    if (bob_secret != NULL)
        free(bob_secret);
    return 1;
}

int main()
{
    x448_key_exchange();

    return EXIT_SUCCESS;
}