/* psa_lms_xmss.c
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

/* Quarantined pending the PSA 1.4 LMS/XMSS rewrite: this legacy code targets
 * the removed <wolfssl/wolfcrypt/lms.h>/<wolfssl/wolfcrypt/xmss.h> headers and
 * key-generation/sign APIs that do not exist under the verify-only build. */
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

#ifdef WOLFSSL_HAVE_LMS
#include <wolfssl/wolfcrypt/lms.h>

/* Generate an LMS key pair */
psa_status_t psa_lms_generate_key(uint8_t *private_key,
                                 size_t private_key_size,
                                 size_t *private_key_length,
                                 uint8_t *public_key,
                                 size_t public_key_size,
                                 size_t *public_key_length)
{
    int ret;
    LmsKey key;
    WC_RNG rng;
    word32 priv_len32;
    word32 pub_len32;
    
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize LMS key */
    ret = wc_LmsKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_LmsKey_MakeKey(&key, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer sizes */
    if (private_key_size < key.privKeyLen || public_key_size < key.pubKeyLen) {
        wc_FreeRng(&rng);
        wc_LmsKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Export private key */
    priv_len32 = (word32)private_key_size;
    ret = wc_LmsKey_ExportPrivate(&key, private_key, &priv_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    pub_len32 = (word32)public_key_size;
    ret = wc_LmsKey_ExportPublic(&key, public_key, &pub_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_FreeRng(&rng);
    wc_LmsKey_Free(&key);

    *private_key_length = (size_t)priv_len32;
    *public_key_length = (size_t)pub_len32;
    
    return PSA_SUCCESS;
}

/* Sign a message with LMS */
psa_status_t psa_lms_sign(const uint8_t *private_key,
                         size_t private_key_size,
                         const uint8_t *message,
                         size_t message_length,
                         uint8_t *signature,
                         size_t signature_size,
                         size_t *signature_length)
{
    int ret;
    LmsKey key;
    word32 sig_len32;
    
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize LMS key */
    ret = wc_LmsKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_LmsKey_ImportPrivate(private_key, (word32)private_key_size, &key);
    if (ret != 0) {
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Sign message */
    sig_len32 = (word32)signature_size;
    ret = wc_LmsKey_Sign(&key, signature, &sig_len32,
                        message, (word32)message_length);
    if (ret != 0) {
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_LmsKey_Free(&key);

    *signature_length = (size_t)sig_len32;
    
    return PSA_SUCCESS;
}

/* Verify a signature with LMS */
psa_status_t psa_lms_verify(const uint8_t *public_key,
                           size_t public_key_size,
                           const uint8_t *message,
                           size_t message_length,
                           const uint8_t *signature,
                           size_t signature_length)
{
    int ret;
    LmsKey key;
    int verify_res = 0;
    
    if ((wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize LMS key */
    ret = wc_LmsKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_LmsKey_ImportPublic(public_key, (word32)public_key_size, &key);
    if (ret != 0) {
        wc_LmsKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Verify signature */
    ret = wc_LmsKey_Verify(&key, signature, (word32)signature_length, 
                          message, (word32)message_length, &verify_res);
    
    wc_LmsKey_Free(&key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
#include <wolfssl/wolfcrypt/xmss.h>

/* Generate an XMSS key pair */
psa_status_t psa_xmss_generate_key(uint8_t *private_key,
                                  size_t private_key_size,
                                  size_t *private_key_length,
                                  uint8_t *public_key,
                                  size_t public_key_size,
                                  size_t *public_key_length)
{
    int ret;
    XmssKey key;
    WC_RNG rng;
    word32 priv_len32;
    word32 pub_len32;
    
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize XMSS key */
    ret = wc_XmssKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Initialize RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate key pair */
    ret = wc_XmssKey_MakeKey(&key, &rng);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Check buffer sizes */
    if (private_key_size < key.privKeyLen || public_key_size < key.pubKeyLen) {
        wc_FreeRng(&rng);
        wc_XmssKey_Free(&key);
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Export private key */
    priv_len32 = (word32)private_key_size;
    ret = wc_XmssKey_ExportPrivate(&key, private_key, &priv_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Export public key */
    pub_len32 = (word32)public_key_size;
    ret = wc_XmssKey_ExportPublic(&key, public_key, &pub_len32);
    if (ret != 0) {
        wc_FreeRng(&rng);
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_FreeRng(&rng);
    wc_XmssKey_Free(&key);

    *private_key_length = (size_t)priv_len32;
    *public_key_length = (size_t)pub_len32;
    
    return PSA_SUCCESS;
}

/* Sign a message with XMSS */
psa_status_t psa_xmss_sign(const uint8_t *private_key,
                          size_t private_key_size,
                          const uint8_t *message,
                          size_t message_length,
                          uint8_t *signature,
                          size_t signature_size,
                          size_t *signature_length)
{
    int ret;
    XmssKey key;
    word32 sig_len32;
    
    if ((wolfpsa_check_word32_length(private_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_size) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize XMSS key */
    ret = wc_XmssKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import private key */
    ret = wc_XmssKey_ImportPrivate(private_key, (word32)private_key_size, &key);
    if (ret != 0) {
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Sign message */
    sig_len32 = (word32)signature_size;
    ret = wc_XmssKey_Sign(&key, signature, &sig_len32,
                         message, (word32)message_length);
    if (ret != 0) {
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    wc_XmssKey_Free(&key);

    *signature_length = (size_t)sig_len32;
    
    return PSA_SUCCESS;
}

/* Verify a signature with XMSS */
psa_status_t psa_xmss_verify(const uint8_t *public_key,
                            size_t public_key_size,
                            const uint8_t *message,
                            size_t message_length,
                            const uint8_t *signature,
                            size_t signature_length)
{
    int ret;
    XmssKey key;
    int verify_res = 0;
    
    if ((wolfpsa_check_word32_length(public_key_size) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(message_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(signature_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize XMSS key */
    ret = wc_XmssKey_Init(&key, NULL, wolfPSA_GetDefaultDevID());
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Import public key */
    ret = wc_XmssKey_ImportPublic(public_key, (word32)public_key_size, &key);
    if (ret != 0) {
        wc_XmssKey_Free(&key);
        return wc_error_to_psa_status(ret);
    }
    
    /* Verify signature */
    ret = wc_XmssKey_Verify(&key, signature, (word32)signature_length, 
                           message, (word32)message_length, &verify_res);
    
    wc_XmssKey_Free(&key);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    if (verify_res != 1) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }
    
    return PSA_SUCCESS;
}
#endif /* WOLFSSL_HAVE_XMSS */

#endif /* WOLFSSL_PSA_ENGINE && (WOLFSSL_HAVE_LMS || WOLFSSL_HAVE_XMSS) */
