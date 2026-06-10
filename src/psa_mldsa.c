/* psa_mldsa.c
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

/* Quarantined pending the PSA 1.4 ML-DSA rewrite: this legacy code uses the
 * removed psa_ml_dsa_parameter_t convention (wolfSSL levels 2/3/5) instead of
 * the spec-mandated seed-based keys with bits 128/192/256. */
#if 0

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

/* Convert ML-DSA parameter to wolfCrypt key type */
static int psa_ml_dsa_parameter_to_type(psa_ml_dsa_parameter_t parameter)
{
    switch (parameter) {
        case PSA_ML_DSA_PARAMETER_2:
            return WC_ML_DSA_44;
        case PSA_ML_DSA_PARAMETER_3:
            return WC_ML_DSA_65;
        case PSA_ML_DSA_PARAMETER_5:
            return WC_ML_DSA_87;
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
    wc_MlDsaKey key;
    int type;
    WC_RNG rng;
    word32 priv_len;
    word32 pub_len;

    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize ML-DSA key */
    ret = wc_MlDsaKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    ret = wc_MlDsaKey_SetParams(&key, (byte)type);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Generate key pair */
    ret = wc_MlDsaKey_MakeKey(&key, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    priv_len = (word32)private_key_size;
    ret = wc_MlDsaKey_ExportPrivRaw(&key, private_key, &priv_len);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    pub_len = (word32)public_key_size;
    ret = wc_MlDsaKey_ExportPubRaw(&key, public_key, &pub_len);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    *private_key_length = priv_len;
    *public_key_length = pub_len;

    wc_FreeRng(&rng);
    wc_MlDsaKey_Free(&key);

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
    wc_MlDsaKey key;
    int type;
    int sig_size;
    WC_RNG rng;
    word32 sigLen;

    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize ML-DSA key */
    ret = wc_MlDsaKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    ret = wc_MlDsaKey_SetParams(&key, (byte)type);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Import private key */
    ret = wc_MlDsaKey_ImportPrivRaw(&key, private_key, (word32)private_key_size);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Check signature buffer size */
    sig_size = wc_MlDsaKey_SigSize(&key);
    if (sig_size < 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(sig_size);
    }
    if (signature_size < (size_t)sig_size) {
        wc_MlDsaKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Sign message (ML-DSA pure, empty context per FIPS 204) */
    sigLen = (word32)signature_size;
    ret = wc_MlDsaKey_SignCtx(&key, NULL, 0,
                              signature, &sigLen,
                              message, (word32)message_length, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    *signature_length = sigLen;

    wc_FreeRng(&rng);
    wc_MlDsaKey_Free(&key);

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
    wc_MlDsaKey key;
    int type;
    int verify_res = 0;

    /* Convert parameter to wolfCrypt key type */
    type = psa_ml_dsa_parameter_to_type(parameter);
    if (type < 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if ((wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize ML-DSA key */
    ret = wc_MlDsaKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    ret = wc_MlDsaKey_SetParams(&key, (byte)type);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Import public key */
    ret = wc_MlDsaKey_ImportPubRaw(&key, public_key, (word32)public_key_size);
    if (ret != 0) {
        wc_MlDsaKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }

    /* Verify signature (ML-DSA pure, empty context per FIPS 204) */
    ret = wc_MlDsaKey_VerifyCtx(&key, signature, (word32)signature_length,
                                NULL, 0,
                                message, (word32)message_length, &verify_res);

    wc_MlDsaKey_Free(&key);

    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFSSL_HAVE_MLDSA */
