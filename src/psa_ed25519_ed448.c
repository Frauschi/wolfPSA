/* psa_ed25519_ed448.c
 *
 * Copyright (C) 2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && (defined(HAVE_ED25519) || defined(HAVE_ED448))

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>

#ifdef HAVE_ED25519
#include <wolfssl/wolfcrypt/ed25519.h>
#endif

#ifdef HAVE_ED448
#include <wolfssl/wolfcrypt/ed448.h>
#endif

#ifdef HAVE_ED25519
/* Sign a hash or short message with an ED25519 private key */
psa_status_t psa_asymmetric_sign_ed25519(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length)
{
    int ret;
    ed25519_key ed_key;
    
    /* Check if key type is ED25519 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED25519 key */
    ret = wc_ed25519_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_ed25519_import_private_key(key_buffer, (word32)key_buffer_size,
                                      NULL, 0, &ed_key);
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Sign message */
    if (alg == PSA_ALG_ED25519PH) {
        /* Sign hash */
        ret = wc_ed25519ph_sign_hash(hash, (word32)hash_length, signature,
                                   (word32*)signature_length, &ed_key, NULL, 0);
    }
    else if (alg == PSA_ALG_ED25519) {
        /* Sign message */
        ret = wc_ed25519_sign_msg(hash, (word32)hash_length, signature,
                                (word32*)signature_length, &ed_key);
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_ed25519_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an ED25519 public key */
psa_status_t psa_asymmetric_verify_ed25519(psa_key_type_t key_type,
                                          size_t key_bits,
                                          const uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          const uint8_t *hash,
                                          size_t hash_length,
                                          const uint8_t *signature,
                                          size_t signature_length)
{
    int ret;
    ed25519_key ed_key;
    int verify_res = 0;
    
    /* Check if key type is ED25519 public key */
    if (key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED25519 key */
    ret = wc_ed25519_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_ed25519_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Verify signature */
    if (alg == PSA_ALG_ED25519PH) {
        /* Verify hash */
        ret = wc_ed25519ph_verify_hash(signature, (word32)signature_length,
                                     hash, (word32)hash_length,
                                     &verify_res, &ed_key);
    }
    else if (alg == PSA_ALG_ED25519) {
        /* Verify message */
        ret = wc_ed25519_verify_msg(signature, (word32)signature_length,
                                  hash, (word32)hash_length,
                                  &verify_res, &ed_key);
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_ed25519_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}

/* Generate an ED25519 key pair */
psa_status_t psa_asymmetric_generate_key_ed25519(psa_key_type_t key_type,
                                                size_t key_bits,
                                                uint8_t *private_key,
                                                size_t private_key_size,
                                                size_t *private_key_length,
                                                uint8_t *public_key,
                                                size_t public_key_size,
                                                size_t *public_key_length)
{
    int ret;
    ed25519_key ed_key;
    WC_RNG rng;
    
    /* Check if key type is ED25519 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED25519 key */
    ret = wc_ed25519_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_ed25519_make_key(&rng, ED25519_KEY_SIZE, &ed_key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export private key */
    ret = wc_ed25519_export_private_only(&ed_key, private_key, (word32*)private_key_length);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    ret = wc_ed25519_export_public(&ed_key, public_key, (word32*)public_key_length);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_FreeRng(&rng);
    wc_ed25519_free(&ed_key);
    
    return PSA_SUCCESS;
}

/* Export an ED25519 public key or the public part of an ED25519 key pair */
psa_status_t psa_asymmetric_export_public_key_ed25519(psa_key_type_t key_type,
                                                     size_t key_bits,
                                                     const uint8_t *key_buffer,
                                                     size_t key_buffer_size,
                                                     uint8_t *output,
                                                     size_t output_size,
                                                     size_t *output_length)
{
    int ret;
    ed25519_key ed_key;
    
    /* Check if key type is ED25519 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) && 
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) || 
        key_bits != 255) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED25519 key */
    ret = wc_ed25519_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import key */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed25519_import_private_key(key_buffer, (word32)key_buffer_size,
                                          NULL, 0, &ed_key);
    }
    else {
        ret = wc_ed25519_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }
    
    if (ret != 0) {
        wc_ed25519_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    ret = wc_ed25519_export_public(&ed_key, output, (word32*)output_length);
    
    wc_ed25519_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_ED448
/* Sign a hash or short message with an ED448 private key */
psa_status_t psa_asymmetric_sign_ed448(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      uint8_t *signature,
                                      size_t signature_size,
                                      size_t *signature_length)
{
    int ret;
    ed448_key ed_key;
    
    /* Check if key type is ED448 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED448 key */
    ret = wc_ed448_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_ed448_import_private_key(key_buffer, (word32)key_buffer_size,
                                    NULL, 0, &ed_key);
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Sign message */
    if (alg == PSA_ALG_ED448PH) {
        /* Sign hash */
        ret = wc_ed448ph_sign_hash(hash, (word32)hash_length, signature,
                                 (word32*)signature_length, &ed_key, NULL, 0);
    }
    else if (alg == PSA_ALG_ED448) {
        /* Sign message */
        ret = wc_ed448_sign_msg(hash, (word32)hash_length, signature,
                              (word32*)signature_length, &ed_key, NULL, 0);
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_ed448_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

/* Verify a signature of a hash or short message with an ED448 public key */
psa_status_t psa_asymmetric_verify_ed448(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *signature,
                                        size_t signature_length)
{
    int ret;
    ed448_key ed_key;
    int verify_res = 0;
    
    /* Check if key type is ED448 public key */
    if (key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED448 key */
    ret = wc_ed448_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_ed448_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Verify signature */
    if (alg == PSA_ALG_ED448PH) {
        /* Verify hash */
        ret = wc_ed448ph_verify_hash(signature, (word32)signature_length,
                                   hash, (word32)hash_length,
                                   &verify_res, &ed_key);
    }
    else if (alg == PSA_ALG_ED448) {
        /* Verify message */
        ret = wc_ed448_verify_msg(signature, (word32)signature_length,
                                hash, (word32)hash_length,
                                &verify_res, &ed_key, NULL, 0);
    }
    else {
        ret = BAD_FUNC_ARG;
    }
    
    wc_ed448_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}

/* Generate an ED448 key pair */
psa_status_t psa_asymmetric_generate_key_ed448(psa_key_type_t key_type,
                                              size_t key_bits,
                                              uint8_t *private_key,
                                              size_t private_key_size,
                                              size_t *private_key_length,
                                              uint8_t *public_key,
                                              size_t public_key_size,
                                              size_t *public_key_length)
{
    int ret;
    ed448_key ed_key;
    WC_RNG rng;
    
    /* Check if key type is ED448 key pair */
    if (key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) || 
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED448 key */
    ret = wc_ed448_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_ed448_make_key(&rng, ED448_KEY_SIZE, &ed_key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export private key */
    ret = wc_ed448_export_private_only(&ed_key, private_key, (word32*)private_key_length);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    ret = wc_ed448_export_public(&ed_key, public_key, (word32*)public_key_length);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_FreeRng(&rng);
    wc_ed448_free(&ed_key);
    
    return PSA_SUCCESS;
}

/* Export an ED448 public key or the public part of an ED448 key pair */
psa_status_t psa_asymmetric_export_public_key_ed448(psa_key_type_t key_type,
                                                   size_t key_bits,
                                                   const uint8_t *key_buffer,
                                                   size_t key_buffer_size,
                                                   uint8_t *output,
                                                   size_t output_size,
                                                   size_t *output_length)
{
    int ret;
    ed448_key ed_key;
    
    /* Check if key type is ED448 */
    if ((key_type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS) && 
         key_type != PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) || 
        key_bits != 448) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize ED448 key */
    ret = wc_ed448_init(&ed_key);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import key */
    if (key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
        ret = wc_ed448_import_private_key(key_buffer, (word32)key_buffer_size,
                                        NULL, 0, &ed_key);
    }
    else {
        ret = wc_ed448_import_public(key_buffer, (word32)key_buffer_size, &ed_key);
    }
    
    if (ret != 0) {
        wc_ed448_free(&ed_key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    ret = wc_ed448_export_public(&ed_key, output, (word32*)output_length);
    
    wc_ed448_free(&ed_key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}
#endif /* HAVE_ED448 */

#endif /* WOLFSSL_PSA_ENGINE && (HAVE_ED25519 || HAVE_ED448) */
