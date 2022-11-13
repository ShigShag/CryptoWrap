/**
 * @file key_exchange.h
 * @author Shig Shag
 * @brief Key exchange
 * @version 0.1
 * @date 2022-11-01
 * 
 * @copyright Copyright (c) 2022 Leon Weinmann
 * 
 */

#ifndef KEY_EXCHANGE_H
#define KEY_EXCHANGE_H

#include "cryptowrap/ecc.h"

#include <stdint.h>

/**
 * @brief Secret is not allocated within the function
 * 
 */
#define KEYEXCH_NO_ALLOC 0x00000001

struct peer_data;

/**
 * @brief Struct to safe a peer object
 * This holds the key used for later key exchange
 * 
 */
typedef struct peer_data *PEER_DATA;

/**
 * @brief Initialize a Elliptic-curve Diffie–Hellman key exchange
 * @details Elliptic curve are defined in ecc.h
 *
 * @param[out] local_peer Where to save the peer object
 * @param[in] curve_id Elliptic curve id to use
 * @return int Returns 1 for success and 0 for failure
 */
int cw_keyexch_dhec_init(PEER_DATA *local_peer, cw_elliptic_curve_type curve_id);

/**
 * @brief Initialize a peer object from an elliptic curve key pair
 * 
 * @param[out] local_peer Where to save the peer object
 * @param[in] key_pair Elliptic curve key pair
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_dhec_init_from_ec(PEER_DATA *local_peer, ECC_KEY_PAIR key_pair);

/**
 * @brief Initialize elliptic curve key pair from a peer object
 * 
 * @param[in] local_peer Local peer object
 * @param[out] key_pair Where to save the elliptic curve key pair
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_dhec_to_ec(PEER_DATA local_peer, ECC_KEY_PAIR key_pair);

/**
 * @brief Derive a shared secret with a local peer object and a peers public key.
 * @details Peers public key must be obtained prior to calling this function
 * 
 * @param[in] local_peer Local peer object
 * @param[in] remote_peer_pubk Remote public key as a byte sequence
 * @param[in] remote_peer_pubk_len Remote public key length
 * @param[out] secret Where to save the secret
 * @param[out] secret_len Optional: Where to save the secret length
 * @param[in] flags 
 *      - KEYEXCH_NO_ALLOC secret is not allocated within the function
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_dhec_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                           uint8_t **secret, uint64_t *secret_len, const uint8_t flags);

/**
 * @brief Initialize a X25519 key exchange
 * @details If a custom key is not set, a random key will be generated
 * 
 * @param[out] local_peer Where to save the peer object
 * @param[in] custom_key Optional: Pointer to custom key if available.
 * Set to NULL to ignore
 * @param[in] custom_key_len Optional: Length of custom key
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_x25519_init(PEER_DATA *local_peer, uint8_t *custom_key, const uint32_t custom_key_len);

/**
 * @brief Derive a shared secret with a local peer object and a peers public key.
 * @details Peers public key must be obtained prior to calling this function
 * 
 * @param[in] local_peer Local peer object
 * @param[in] remote_peer_pubk Remote public key as a byte sequence
 * @param[in] remote_peer_pubk_len Remote public key length
 * @param[out] secret Where to save the secret
 * @param[out] secret_len Optional: Where to save the secret length
 * @param[in] flags 
 *      - KEYEXCH_NO_ALLOC secret is not allocated within the function
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_x25519_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                             uint8_t **secret, uint64_t *secret_len, const uint8_t flags);

/**
 * @brief Initialize a X448 key exchange
 * @details If a custom key is not set, a random key will be generated
 * 
 * @param[out] local_peer Where to save the peer object
 * @param[in] custom_key Optional: Pointer to custom key if available.
 * Set to NULL to ignore
 * @param[in] custom_key_len Optional: Length of custom key
 * @return int Returns 1 for success and 0 for failure  
 */
int cw_keyexch_x448_init(PEER_DATA *local_peer, uint8_t *custom_key, const uint32_t custom_key_len);

/**
 * @brief Derive a shared secret with a local peer object and a peers public key.
 * @details Peers public key must be obtained prior to calling this function
 * 
 * @param[in] local_peer Local peer object
 * @param[in] remote_peer_pubk Remote public key as a byte sequence
 * @param[in] remote_peer_pubk_len Remote public key length
 * @param[out] secret Where to save the secret
 * @param[out] secret_len Optional: Where to save the secret length
 * @param[in] flags 
 *      - KEYEXCH_NO_ALLOC secret is not allocated within the function
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_x448_derive(PEER_DATA local_peer, uint8_t *remote_peer_pubk, const uint32_t remote_peer_pubk_len,
                           uint8_t **secret, uint64_t *secret_len, const uint8_t flags);

/**
 * @brief Extract the public key as a byte sequence from a peer object.
 * @details The byte sequence should be send to other parties who then can create a shared secret
 * 
 * @param[in] local_peer Local peer object from which to extract the public key
 * @param[out] pub_key Where to save the public key
 * @param[out] pub_key_len Optional: Where to save the public key length
 * @param[in] flags 
 *      - KEYEXCH_NO_ALLOC secret is not allocated within the function
 * @return int Returns 1 for success and 0 for failure 
 */
int cw_keyexch_peer_get_pub_key(PEER_DATA local_peer, uint8_t **pub_key, uint32_t *pub_key_len, const uint8_t flags);

/**
 * @brief Delete a peer data object 
 * 
 * @param[in] local_peer Peer object to delete
 */
void cw_keyexch_peer_data_delete(PEER_DATA local_peer);

#endif