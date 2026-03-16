/* psa_asymmetric_api.c
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

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include "psa_trace.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_key_storage.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/ecc.h>

extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);

psa_status_t psa_asymmetric_sign_rsa(psa_key_type_t key_type,
                                    size_t key_bits,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length);
psa_status_t psa_asymmetric_verify_rsa(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length);
psa_status_t psa_asymmetric_encrypt_rsa(psa_key_type_t key_type,
                                       size_t key_bits,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *input,
                                       size_t input_length,
                                       const uint8_t *salt,
                                       size_t salt_length,
                                       uint8_t *output,
                                       size_t output_size,
                                       size_t *output_length);
psa_status_t psa_asymmetric_decrypt_rsa(psa_key_type_t key_type,
                                       size_t key_bits,
                                       const uint8_t *key_buffer,
                                       size_t key_buffer_size,
                                       psa_algorithm_t alg,
                                       const uint8_t *input,
                                       size_t input_length,
                                       const uint8_t *salt,
                                       size_t salt_length,
                                       uint8_t *output,
                                       size_t output_size,
                                       size_t *output_length);
psa_status_t psa_asymmetric_sign_ecc(psa_key_type_t key_type,
                                    size_t key_bits,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    psa_algorithm_t alg,
                                    const uint8_t *hash,
                                    size_t hash_length,
                                    uint8_t *signature,
                                    size_t signature_size,
                                    size_t *signature_length);
psa_status_t psa_asymmetric_verify_ecc(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      const uint8_t *signature,
                                      size_t signature_length);
#ifdef HAVE_ED25519
psa_status_t psa_asymmetric_sign_ed25519(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        uint8_t *signature,
                                        size_t signature_size,
                                        size_t *signature_length);
psa_status_t psa_asymmetric_verify_ed25519(psa_key_type_t key_type,
                                          size_t key_bits,
                                          const uint8_t *key_buffer,
                                          size_t key_buffer_size,
                                          psa_algorithm_t alg,
                                          const uint8_t *hash,
                                          size_t hash_length,
                                          const uint8_t *signature,
                                          size_t signature_length);
#endif
#ifdef HAVE_ED448
psa_status_t psa_asymmetric_sign_ed448(psa_key_type_t key_type,
                                      size_t key_bits,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      psa_algorithm_t alg,
                                      const uint8_t *hash,
                                      size_t hash_length,
                                      uint8_t *signature,
                                      size_t signature_size,
                                      size_t *signature_length);
psa_status_t psa_asymmetric_verify_ed448(psa_key_type_t key_type,
                                        size_t key_bits,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t *hash,
                                        size_t hash_length,
                                        const uint8_t *signature,
                                        size_t signature_length);
#endif

static psa_status_t wolfpsa_asymmetric_check_key(psa_key_id_t key,
                                                 psa_key_usage_t usage,
                                                 psa_algorithm_t alg,
                                                 psa_key_attributes_t *attributes,
                                                 uint8_t **key_data,
                                                 size_t *key_data_length)
{
    psa_status_t status;
    psa_key_usage_t key_usage;
    psa_algorithm_t key_alg;

    status = wolfpsa_get_key_data(key, attributes, key_data, key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key_usage = psa_get_key_usage_flags(attributes);
    if ((key_usage & usage) == 0) {
        wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
        *key_data = NULL;
        *key_data_length = 0;
        return PSA_ERROR_NOT_PERMITTED;
    }

    key_alg = psa_get_key_algorithm(attributes);
    if (key_alg != PSA_ALG_NONE) {
        if (PSA_ALG_IS_KEY_AGREEMENT(alg) && PSA_ALG_IS_KEY_AGREEMENT(key_alg)) {
            if (PSA_ALG_KEY_AGREEMENT_GET_BASE(key_alg) !=
                PSA_ALG_KEY_AGREEMENT_GET_BASE(alg)) {
                wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
                *key_data = NULL;
                *key_data_length = 0;
                return PSA_ERROR_NOT_PERMITTED;
            }
        }
        else if (key_alg != alg) {
            wolfpsa_forcezero_free_key_data(*key_data, *key_data_length);
            *key_data = NULL;
            *key_data_length = 0;
            return PSA_ERROR_NOT_PERMITTED;
        }
    }

    return PSA_SUCCESS;
}

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_ENCRYPT, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        if (output == NULL) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_asymmetric_encrypt_rsa(attributes.type, attributes.bits,
                                            key_data, key_data_length,
                                            alg, input, input_length,
                                            salt, salt_length,
                                            output, output_size, output_length);
    }
    else {
        status = PSA_KEY_TYPE_IS_ASYMMETRIC(attributes.type) ?
            PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                   psa_algorithm_t alg,
                                   const uint8_t *input,
                                   size_t input_length,
                                   const uint8_t *salt,
                                   size_t salt_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_DECRYPT, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        if (output == NULL) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_asymmetric_decrypt_rsa(attributes.type, attributes.bits,
                                            key_data, key_data_length,
                                            alg, input, input_length,
                                            salt, salt_length,
                                            output, output_size, output_length);
    }
    else {
        status = PSA_KEY_TYPE_IS_ASYMMETRIC(attributes.type) ?
            PSA_ERROR_NOT_SUPPORTED : PSA_ERROR_INVALID_ARGUMENT;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t *hash,
                           size_t hash_length,
                           uint8_t *signature,
                           size_t signature_size,
                           size_t *signature_length)
{
    wolfpsa_trace("psa_sign_hash(key=%u alg=0x%08x hash_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length);
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (hash == NULL || signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_SIGN_HASH, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_sign_rsa(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_sign_ecc(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_sign_ed25519(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_size,
                                                 signature_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_sign_ed448(attributes.type, attributes.bits,
                                               key_data, key_data_length,
                                               alg, hash, hash_length,
                                               signature, signature_size,
                                               signature_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t *hash,
                             size_t hash_length,
                             const uint8_t *signature,
                             size_t signature_length)
{
    wolfpsa_trace("psa_verify_hash(key=%u alg=0x%08x hash_len=%zu sig_len=%zu)",
                  (unsigned)key, (unsigned)alg, hash_length, signature_length);
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;

    if (hash == NULL || signature == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_VERIFY_HASH, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_verify_rsa(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_verify_ecc(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_verify_ed25519(attributes.type, attributes.bits,
                                                   key_data, key_data_length,
                                                   alg, hash, hash_length,
                                                   signature, signature_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_verify_ed448(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t *input,
                              size_t input_length,
                              uint8_t *signature,
                              size_t signature_size,
                              size_t *signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_length = 0;
    psa_status_t status;

    if (input == NULL || signature == NULL || signature_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_SIGN_MESSAGE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        hash_alg = 0;
        hash_length = input_length;
        if (hash_length > sizeof(hash)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        XMEMCPY(hash, input, hash_length);
    }
    else {
        hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        if (hash_alg == 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }

        status = psa_hash_compute(hash_alg, input, input_length,
                                  hash, sizeof(hash), &hash_length);
        if (status != PSA_SUCCESS) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_sign_rsa(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_sign_ecc(attributes.type, attributes.bits,
                                         key_data, key_data_length,
                                         alg, hash, hash_length,
                                         signature, signature_size,
                                         signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_sign_ed25519(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_size,
                                                 signature_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_sign_ed448(attributes.type, attributes.bits,
                                               key_data, key_data_length,
                                               alg, hash, hash_length,
                                               signature, signature_size,
                                               signature_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t *input,
                                size_t input_length,
                                const uint8_t *signature,
                                size_t signature_length)
{
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_algorithm_t hash_alg;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_length = 0;
    psa_status_t status;

    if (input == NULL || signature == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = wolfpsa_asymmetric_check_key(key, PSA_KEY_USAGE_VERIFY_MESSAGE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (alg == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
        hash_alg = 0;
        hash_length = input_length;
        if (hash_length > sizeof(hash)) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        XMEMCPY(hash, input, hash_length);
    }
    else {
        hash_alg = PSA_ALG_SIGN_GET_HASH(alg);
        if (hash_alg == 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }

        status = psa_hash_compute(hash_alg, input, input_length,
                                  hash, sizeof(hash), &hash_length);
        if (status != PSA_SUCCESS) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return status;
        }
    }

    if (PSA_KEY_TYPE_IS_RSA(attributes.type)) {
        status = psa_asymmetric_verify_rsa(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
    else if (PSA_KEY_TYPE_IS_ECC(attributes.type)) {
        status = psa_asymmetric_verify_ecc(attributes.type, attributes.bits,
                                           key_data, key_data_length,
                                           alg, hash, hash_length,
                                           signature, signature_length);
    }
#if defined(HAVE_ED25519) || defined(HAVE_ED448)
    else if (attributes.type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS)) {
    #ifdef HAVE_ED25519
        if (attributes.bits == 255) {
            status = psa_asymmetric_verify_ed25519(attributes.type, attributes.bits,
                                                   key_data, key_data_length,
                                                   alg, hash, hash_length,
                                                   signature, signature_length);
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (attributes.bits == 448) {
            status = psa_asymmetric_verify_ed448(attributes.type, attributes.bits,
                                                 key_data, key_data_length,
                                                 alg, hash, hash_length,
                                                 signature, signature_length);
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
        }
    }
#endif
    else {
        status = PSA_ERROR_NOT_SUPPORTED;
    }

    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    return status;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t *peer_key,
                                   size_t peer_key_length,
                                   uint8_t *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    wolfpsa_trace("psa_raw_key_agreement(alg=0x%08x key=%u peer_len=%zu)",
                  (unsigned)alg, (unsigned)private_key, peer_key_length);
    psa_key_attributes_t attributes;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    psa_status_t status;
    int ret;
    ecc_key priv;
    ecc_key pub;
    int curve_id;
    word32 out_len;

    if (output == NULL || output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (!PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) != PSA_ALG_ECDH) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = wolfpsa_asymmetric_check_key(private_key, PSA_KEY_USAGE_DERIVE, alg,
                                          &attributes, &key_data, &key_data_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    if (!PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes.type)) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    curve_id = wc_psa_get_ecc_curve_id(attributes.type, attributes.bits);
    if (curve_id == ECC_CURVE_INVALID) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_NOT_SUPPORTED;
    }

    {
        size_t expected_secret_len;

        expected_secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(attributes.type,
                                                                attributes.bits);
        if (expected_secret_len == 0) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (output_size < expected_secret_len) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_BUFFER_TOO_SMALL;
        }
    }

    if (peer_key == NULL && peer_key_length > 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    {
        size_t coord_len = PSA_BITS_TO_BYTES(attributes.bits);
        size_t expected_peer_len = 1u + 2u * coord_len;

        if (peer_key_length != expected_peer_len ||
            peer_key[0] != 0x04) {
            wolfpsa_forcezero_free_key_data(key_data, key_data_length);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    ret = wc_ecc_init(&priv);
    if (ret != 0) {
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }
    ret = wc_ecc_init(&pub);
    if (ret != 0) {
        wc_ecc_free(&priv);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }

    ret = wc_ecc_import_private_key_ex(key_data, (word32)key_data_length,
                                       NULL, 0, &priv, curve_id);
    if (ret == 0) {
        ret = wc_ecc_make_pub_ex(&priv, NULL, NULL);
    }
    if (ret == 0) {
        ret = wc_ecc_import_x963(peer_key, (word32)peer_key_length, &pub);
    }
    if (ret != 0) {
        wc_ecc_free(&pub);
        wc_ecc_free(&priv);
        wolfpsa_forcezero_free_key_data(key_data, key_data_length);
        return wc_error_to_psa_status(ret);
    }

    out_len = (word32)output_size;
    ret = wc_ecc_shared_secret(&priv, &pub, output, &out_len);
    wc_ecc_free(&pub);
    wc_ecc_free(&priv);
    wolfpsa_forcezero_free_key_data(key_data, key_data_length);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    *output_length = (size_t)out_len;
    return PSA_SUCCESS;
}

psa_status_t psa_key_agreement(psa_key_id_t private_key,
                               const uint8_t *peer_key,
                               size_t peer_key_length,
                               psa_algorithm_t alg,
                               const psa_key_attributes_t *attributes,
                               psa_key_id_t *key)
{
    uint8_t *secret = NULL;
    size_t secret_len;
    size_t output_len = 0;
    psa_status_t status;
    psa_algorithm_t kdf_alg;
    psa_key_attributes_t priv_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_derivation_operation_t kdf_op = PSA_KEY_DERIVATION_OPERATION_INIT;

    if (attributes == NULL || key == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *key = PSA_KEY_ID_NULL;

    if (!PSA_ALG_IS_KEY_AGREEMENT(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = psa_get_key_attributes(private_key, &priv_attr);
    if (status != PSA_SUCCESS) {
        return status;
    }

    secret_len = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(priv_attr.type,
                                                   priv_attr.bits);
    if (secret_len == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    secret = (uint8_t *)XMALLOC(secret_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (secret == NULL) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    status = psa_raw_key_agreement(alg, private_key, peer_key, peer_key_length,
                                   secret, secret_len, &output_len);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    kdf_alg = PSA_ALG_KEY_AGREEMENT_GET_KDF(alg);
    if (kdf_alg == PSA_ALG_CATEGORY_KEY_DERIVATION) {
        psa_key_type_t out_type = psa_get_key_type(attributes);

        if (out_type != PSA_KEY_TYPE_DERIVE &&
            out_type != PSA_KEY_TYPE_RAW_DATA) {
            wc_ForceZero(secret, secret_len);
            XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return PSA_ERROR_INVALID_ARGUMENT;
        }
        status = psa_import_key(attributes, secret, output_len, key);
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    status = psa_key_derivation_setup(&kdf_op, kdf_alg);
    if (status != PSA_SUCCESS) {
        wc_ForceZero(secret, secret_len);
        XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return status;
    }

    status = psa_key_derivation_input_bytes(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                            secret, output_len);
    wc_ForceZero(secret, secret_len);
    XFREE(secret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (status != PSA_SUCCESS) {
        psa_key_derivation_abort(&kdf_op);
        return status;
    }

    status = psa_key_derivation_output_key(attributes, &kdf_op, key);
    psa_key_derivation_abort(&kdf_op);
    return status;
}

#endif /* WOLFSSL_PSA_ENGINE */
