/* psa_mlkem.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && (defined(WOLFSSL_HAVE_KYBER) || defined(WOLFSSL_WC_MLKEM))

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/mlkem.h>

/* Convert ML-KEM parameter to wolfCrypt key type */
static int psa_ml_kem_parameter_to_type(psa_ml_kem_parameter_t parameter)
{
    switch (parameter) {
        case PSA_ML_KEM_PARAMETER_512:
            return WC_ML_KEM_512;
        case PSA_ML_KEM_PARAMETER_768:
            return WC_ML_KEM_768;
        case PSA_ML_KEM_PARAMETER_1024:
            return WC_ML_KEM_1024;
        default:
            return -1;
    }
}

/* Generate an ML-KEM key pair */
psa_status_t psa_ml_kem_generate_key(psa_ml_kem_parameter_t parameter,
                                    uint8_t *private_key,
                                    size_t private_key_size,
                                    size_t *private_key_length,
                                    uint8_t *public_key,
                                    size_t public_key_size,
                                    size_t *public_key_length)
{
    int ret;
    MlKemKey key;
    int type;
    WC_RNG rng;
    word32 privSz, pubSz;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_kem_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-KEM key */
    ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_MlKemKey_MakeKey(&key, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get key sizes */
    ret = wc_MlKemKey_PrivateKeySize(&key, &privSz);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    ret = wc_MlKemKey_PublicKeySize(&key, &pubSz);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer sizes */
    if (private_key_size < privSz || public_key_size < pubSz) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Export private key */
    ret = wc_MlKemKey_EncodePrivateKey(&key, private_key, privSz);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    *private_key_length = privSz;
    
    /* Export public key */
    ret = wc_MlKemKey_EncodePublicKey(&key, public_key, pubSz);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    *public_key_length = pubSz;
    
    wc_FreeRng(&rng);
    wc_MlKemKey_Free(&key);
    
    return PSA_SUCCESS;
}

/* Encapsulate a shared secret */
psa_status_t psa_ml_kem_encapsulate(psa_ml_kem_parameter_t parameter,
                                   const uint8_t *public_key,
                                   size_t public_key_size,
                                   uint8_t *ciphertext,
                                   size_t ciphertext_size,
                                   size_t *ciphertext_length,
                                   uint8_t *shared_secret,
                                   size_t shared_secret_size,
                                   size_t *shared_secret_length)
{
    int ret;
    MlKemKey key;
    int type;
    WC_RNG rng;
    word32 ctSz, ssSz;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_kem_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-KEM key */
    ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_MlKemKey_DecodePublicKey(&key, public_key, (word32)public_key_size);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get ciphertext and shared secret sizes */
    ret = wc_MlKemKey_CipherTextSize(&key, &ctSz);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    ret = wc_MlKemKey_SharedSecretSize(&key, &ssSz);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer sizes */
    if (ciphertext_size < ctSz || shared_secret_size < ssSz) {
        wc_MlKemKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Encapsulate shared secret */
    ret = wc_MlKemKey_Encapsulate(&key, ciphertext, shared_secret, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    *ciphertext_length = ctSz;
    *shared_secret_length = ssSz;
    
    wc_FreeRng(&rng);
    wc_MlKemKey_Free(&key);
    
    return PSA_SUCCESS;
}

/* Decapsulate a shared secret */
psa_status_t psa_ml_kem_decapsulate(psa_ml_kem_parameter_t parameter,
                                   const uint8_t *private_key,
                                   size_t private_key_size,
                                   const uint8_t *ciphertext,
                                   size_t ciphertext_size,
                                   uint8_t *shared_secret,
                                   size_t shared_secret_size,
                                   size_t *shared_secret_length)
{
    int ret;
    MlKemKey key;
    int type;
    word32 ssSz;
    
    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_kem_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Initialize ML-KEM key */
    ret = wc_MlKemKey_Init(&key, type, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_MlKemKey_DecodePrivateKey(&key, private_key, (word32)private_key_size);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Get shared secret size */
    ret = wc_MlKemKey_SharedSecretSize(&key, &ssSz);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer size */
    if (shared_secret_size < ssSz) {
        wc_MlKemKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Decapsulate shared secret */
    ret = wc_MlKemKey_Decapsulate(&key, shared_secret, ciphertext, 
                                 (word32)ciphertext_size);
    if (ret != 0) {
        wc_MlKemKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    *shared_secret_length = ssSz;
    
    wc_MlKemKey_Free(&key);
    
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && (WOLFSSL_HAVE_KYBER || WOLFSSL_WC_MLKEM) */
