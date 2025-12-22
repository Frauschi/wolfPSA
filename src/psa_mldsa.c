/* psa_mldsa.c
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

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFSSL_HAVE_DILITHIUM)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/dilithium.h>

/* Convert ML-DSA parameter to wolfCrypt key type */
static int psa_ml_dsa_parameter_to_type(psa_ml_dsa_parameter_t parameter)
{
    switch (parameter) {
        case PSA_ML_DSA_PARAMETER_2:
            return DILITHIUM_LEVEL2;
        case PSA_ML_DSA_PARAMETER_3:
            return DILITHIUM_LEVEL3;
        case PSA_ML_DSA_PARAMETER_5:
            return DILITHIUM_LEVEL5;
        default:
            return -1;
    }
}

/* Generate an ML-DSA key pair */
psa_status_t psa_ml_dsa_generate_key(psa_ml_dsa_parameter_t parameter,
                                    uint8_t *private_key,
                                    size_t private_key_size,
                                    size_t *private_key_length,
                                    uint8_t *public_key,
                                    size_t public_key_size,
                                    size_t *public_key_length)
{
    int ret;
    dilithium_key key;
    int type;
    WC_RNG rng;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-DSA key */
    ret = wc_dilithium_init_ex(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_dilithium_make_key(&rng, &key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_dilithium_free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer sizes */
    if (private_key_size < key.priv_key_len || public_key_size < key.pub_key_len) {
        wc_FreeRng(&rng);
        wc_dilithium_free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Export private key */
    XMEMCPY(private_key, key.k, key.priv_key_len);
    *private_key_length = key.priv_key_len;
    
    /* Export public key */
    XMEMCPY(public_key, key.p, key.pub_key_len);
    *public_key_length = key.pub_key_len;
    
    wc_FreeRng(&rng);
    wc_dilithium_free(&key);
    
    return PSA_SUCCESS;
}

/* Sign a message with ML-DSA */
psa_status_t psa_ml_dsa_sign(psa_ml_dsa_parameter_t parameter,
                            const uint8_t *private_key,
                            size_t private_key_size,
                            const uint8_t *message,
                            size_t message_length,
                            uint8_t *signature,
                            size_t signature_size,
                            size_t *signature_length)
{
    int ret;
    dilithium_key key;
    int type;
    word32 sigLen;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-DSA key */
    ret = wc_dilithium_init_ex(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_dilithium_import_private(private_key, (word32)private_key_size, &key);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check signature buffer size */
    if (signature_size < key.sig_len) {
        wc_dilithium_free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Sign message */
    sigLen = (word32)signature_size;
    ret = wc_dilithium_sign_msg(message, (word32)message_length, signature, 
                               &sigLen, &key);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return wc_error_to_psa_status(ret);
    }
    *signature_length = sigLen;
    
    wc_dilithium_free(&key);
    
    return PSA_SUCCESS;
}

/* Verify a signature with ML-DSA */
psa_status_t psa_ml_dsa_verify(psa_ml_dsa_parameter_t parameter,
                              const uint8_t *public_key,
                              size_t public_key_size,
                              const uint8_t *message,
                              size_t message_length,
                              const uint8_t *signature,
                              size_t signature_length)
{
    int ret;
    dilithium_key key;
    int type;
    int verify_res = 0;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-DSA key */
    ret = wc_dilithium_init_ex(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_dilithium_import_public(public_key, (word32)public_key_size, &key);
    if (ret != 0) {
        wc_dilithium_free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Verify signature */
    ret = wc_dilithium_verify_msg(signature, (word32)signature_length, message, 
                                 (word32)message_length, &verify_res, &key);
    
    wc_dilithium_free(&key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFSSL_HAVE_DILITHIUM */
