/* psa_opaque_driver.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfPSA.
 *
 * wolfPSA is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfPSA is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFPSA_OPAQUE_DRIVER_H
#define WOLFPSA_OPAQUE_DRIVER_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <psa/crypto.h>
#include <wolfpsa/psa_locations.h>

#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifndef NO_AES
    #include <wolfssl/wolfcrypt/aes.h>
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    #include <wolfssl/wolfcrypt/cmac.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A driver owning the keys at one key location, in the sense the PSA unified
 * driver model gives the word: keys wolfPSA cannot see. What it stores for such
 * a key is whatever reference the driver serialises, handed back on every
 * operation. Keys in local storage are not a driver's business - the generic
 * code holds their material itself.
 *
 * Only validate is mandatory. Every other op may be NULL, which is how a driver
 * declines one: the caller reports PSA_ERROR_NOT_SUPPORTED without knowing what
 * it asked for. A driver that keeps no private material leaves export_private,
 * copy and key_agreement NULL; one built on a device that can release a wrapped
 * copy fills them in, and no generic code changes.
 */
typedef struct wolfpsa_opaque_driver {
    psa_key_location_t location;

    /* A second value this driver also answers to, so an application written
     * against another implementation's constant for the same hardware needs no
     * edit. PSA_KEY_LOCATION_LOCAL_STORAGE means there is none, since no driver
     * can own that one. */
    psa_key_location_t location_alias;

    /* Upper bound on what generate, copy, unwrap and derive write, for the
     * caller's buffer. */
    size_t max_key_data_size;

    /* Reject attributes, or key material, this driver cannot own, before
     * anything is stored. data is NULL when there is no material to screen
     * yet, which is how a generation asks about the attributes alone. Every
     * op that produces a key may assume this has passed. */
    psa_status_t (*validate)(const psa_key_attributes_t* attributes,
                             const uint8_t* data, size_t data_length);

    /* Create a key in the driver and serialise what wolfPSA stores for it. */
    psa_status_t (*generate)(const psa_key_attributes_t* attributes,
                             uint8_t* key_data, size_t key_data_size,
                             size_t* key_data_length);

    /* Release the key the material names. */
    psa_status_t (*destroy)(const psa_key_attributes_t* attributes,
                            const uint8_t* key_data, size_t key_data_length);

    /* The public key, in the PSA export format for its type. */
    psa_status_t (*export_public)(const psa_key_attributes_t* attributes,
                                  const uint8_t* key_data,
                                  size_t key_data_length,
                                  uint8_t* data, size_t data_size,
                                  size_t* data_length);

    /* The key itself, in the PSA export format for its type. The caller has
     * already checked PSA_KEY_USAGE_EXPORT. */
    psa_status_t (*export_private)(const psa_key_attributes_t* attributes,
                                   const uint8_t* key_data,
                                   size_t key_data_length,
                                   uint8_t* data, size_t data_size,
                                   size_t* data_length);

    /* A second key with the same material and the target attributes, which the
     * caller has already checked against the source. It must be independent:
     * destroying either may not disturb the other. */
    psa_status_t (*copy)(const psa_key_attributes_t* attributes,
                         const uint8_t* key_data, size_t key_data_length,
                         const psa_key_attributes_t* target,
                         uint8_t* new_key_data, size_t new_key_data_size,
                         size_t* new_key_data_length);

    /* The raw shared secret, for every agreement entry point. */
    psa_status_t (*key_agreement)(const psa_key_attributes_t* attributes,
                                  const uint8_t* key_data,
                                  size_t key_data_length, psa_algorithm_t alg,
                                  const uint8_t* peer_key,
                                  size_t peer_key_length,
                                  uint8_t* output, size_t output_size,
                                  size_t* output_length);

    /* Emit the key wrapped under the wrapping key, which is at this same
     * location; the caller has checked both policies. */
    psa_status_t (*wrap)(const psa_key_attributes_t* wrap_attributes,
                         const uint8_t* wrap_key_data,
                         size_t wrap_key_data_length, psa_algorithm_t alg,
                         const psa_key_attributes_t* attributes,
                         const uint8_t* key_data, size_t key_data_length,
                         uint8_t* data, size_t data_size, size_t* data_length);

    /* Take a wrapped blob into the driver and serialise the new key. */
    psa_status_t (*unwrap)(const psa_key_attributes_t* wrap_attributes,
                           const uint8_t* wrap_key_data,
                           size_t wrap_key_data_length, psa_algorithm_t alg,
                           const psa_key_attributes_t* attributes,
                           const uint8_t* data, size_t data_length,
                           uint8_t* key_data, size_t key_data_size,
                           size_t* key_data_length);

    /* Derive a new driver key from a driver key, with neither in memory. The
     * derivation input is whatever the KDF has collected. */
    psa_status_t (*derive)(const psa_key_attributes_t* attributes,
                           const psa_key_attributes_t* src_attributes,
                           const uint8_t* src_key_data,
                           size_t src_key_data_length, psa_algorithm_t alg,
                           const uint8_t* input, size_t input_length,
                           uint8_t* key_data, size_t key_data_size,
                           size_t* key_data_length);

#ifdef HAVE_ECC
    /* Initialise key and bind it to the driver key the material names, so a
     * wc_ecc_* operation reaches the hardware. The caller owns an initialised
     * key only on success, and frees it with wc_ecc_free(). curve_id already
     * carries the key size, so no attributes are needed. */
    psa_status_t (*ecc_bind)(const uint8_t* key_data, size_t key_data_length,
                             int curve_id, psa_algorithm_t alg, ecc_key* key);
#endif

#ifndef NO_AES
    /* Same, for an Aes: on success it is initialised and keyed, and the caller
     * frees it with wc_AesFree(). No IV is set, since the mode decides that. */
    psa_status_t (*aes_bind)(const uint8_t* key_data, size_t key_data_length,
                             psa_algorithm_t alg, Aes* aes);
#endif

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    /* Same, for a Cmac, which on this hardware is a separate permission from
     * the cipher and so may need its own reference. */
    psa_status_t (*cmac_bind)(const uint8_t* key_data, size_t key_data_length,
                              psa_algorithm_t alg, Cmac* cmac);
#endif
} wolfpsa_opaque_driver;

/* The driver owning this lifetime, or NULL - which covers local storage, an
 * unknown location, and a location whose driver this build left out. */
const wolfpsa_opaque_driver* wolfpsa_opaque_driver_find(psa_key_lifetime_t
                                                        lifetime);

/* PSA_SUCCESS when the key material is wolfPSA's own to use, and
 * PSA_ERROR_NOT_SUPPORTED when a driver owns it. For the paths that need
 * plaintext material and have no op to ask for it, where using key_data
 * directly would run the algorithm over a key reference. */
psa_status_t wolfpsa_opaque_driver_reject(psa_key_lifetime_t lifetime);

#ifdef __cplusplus
}
#endif

#endif /* WOLFPSA_OPAQUE_DRIVER_H */
