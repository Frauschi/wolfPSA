/* psa_tls_prf.c
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

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFSSL_TLS13) && \
    defined(HAVE_HKDF) && !defined(NO_HMAC)

#include <psa/crypto.h>
#include "psa_size.h"
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_tls_prf.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/kdf.h>

/* Check if TLS PRF algorithm is supported */
psa_status_t psa_tls_prf_check_alg_supported(psa_algorithm_t alg)
{
    if (PSA_ALG_IS_TLS13_PRF(alg)) {
        /* Check if the hash algorithm is supported */
        switch (PSA_ALG_HASH_FROM_TLS13_PRF(alg)) {
            case PSA_ALG_SHA_256:
            case PSA_ALG_SHA_384:
                return PSA_SUCCESS;
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    }
    
    return PSA_ERROR_NOT_SUPPORTED;
}

/* Get the hash algorithm from TLS 1.3 PRF algorithm */
static int psa_tls13_get_hash_type(psa_algorithm_t alg, enum wc_HashType* hashType)
{
    psa_algorithm_t hash_alg = PSA_ALG_HASH_FROM_TLS13_PRF(alg);
    
    switch (hash_alg) {
        case PSA_ALG_SHA_256:
            *hashType = WC_HASH_TYPE_SHA256;
            return 0;
        case PSA_ALG_SHA_384:
            *hashType = WC_HASH_TYPE_SHA384;
            return 0;
        default:
            return -1;
    }
}

/* TLS 1.3 PRF (HKDF) */
psa_status_t psa_tls13_prf(
    psa_algorithm_t alg,
    const uint8_t *secret, size_t secret_length,
    const uint8_t *label, size_t label_length,
    const uint8_t *context, size_t context_length,
    uint8_t *output, size_t output_length)
{
    int ret;
    enum wc_HashType hashType;
    
    /* Check parameters */
    if (!PSA_ALG_IS_TLS13_PRF(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (secret == NULL && secret_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (label == NULL && label_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (context == NULL && context_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (output == NULL || output_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(secret_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(label_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(context_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Get hash type */
    ret = psa_tls13_get_hash_type(alg, &hashType);
    if (ret != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Perform TLS 1.3 PRF operation */
    ret = wc_Tls13_HKDF_Expand_Label(
        output, (word32)output_length,
        secret, (word32)secret_length,
        NULL, 0,  /* protocol */
        label, (word32)label_length,
        context, (word32)context_length,
        hashType
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

/* TLS 1.3 HKDF Extract */
psa_status_t psa_tls13_hkdf_extract(
    psa_algorithm_t alg,
    const uint8_t *salt, size_t salt_length,
    const uint8_t *ikm, size_t ikm_length,
    uint8_t *output, size_t output_size, size_t *output_length)
{
    int ret;
    enum wc_HashType hashType;
    int hashLen;
    
    /* Check parameters */
    if (!PSA_ALG_IS_TLS13_PRF(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (salt == NULL && salt_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (ikm == NULL && ikm_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (output == NULL || output_size == 0 || output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(salt_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(ikm_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Get hash type */
    ret = psa_tls13_get_hash_type(alg, &hashType);
    if (ret != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Get hash length */
    ret = wc_HashGetDigestSize(hashType);
    if (ret < 0) {
        return wc_error_to_psa_status(ret);
    }
    hashLen = ret;
    
    /* Check output buffer size */
    if (output_size < (size_t)hashLen) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    
    /* Perform HKDF Extract operation */
    ret = wc_HKDF_Extract(
        hashType,
        salt, (word32)salt_length,
        ikm, (word32)ikm_length,
        output
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    *output_length = hashLen;
    
    return PSA_SUCCESS;
}

/* TLS 1.3 HKDF Expand */
psa_status_t psa_tls13_hkdf_expand(
    psa_algorithm_t alg,
    const uint8_t *prk, size_t prk_length,
    const uint8_t *info, size_t info_length,
    uint8_t *output, size_t output_length)
{
    int ret;
    enum wc_HashType hashType;
    
    /* Check parameters */
    if (!PSA_ALG_IS_TLS13_PRF(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (prk == NULL || prk_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (info == NULL && info_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (output == NULL || output_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(prk_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(info_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Get hash type */
    ret = psa_tls13_get_hash_type(alg, &hashType);
    if (ret != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Perform HKDF Expand operation */
    ret = wc_HKDF_Expand(
        hashType,
        prk, (word32)prk_length,
        info, (word32)info_length,
        output, (word32)output_length
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

/* TLS 1.3 HKDF Expand Label */
psa_status_t psa_tls13_hkdf_expand_label(
    psa_algorithm_t alg,
    const uint8_t *secret, size_t secret_length,
    const uint8_t *label, size_t label_length,
    const uint8_t *context, size_t context_length,
    uint8_t *output, size_t output_length)
{
    int ret;
    enum wc_HashType hashType;
    
    /* Check parameters */
    if (!PSA_ALG_IS_TLS13_PRF(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    if (secret == NULL && secret_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (label == NULL && label_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (context == NULL && context_length > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    if (output == NULL || output_length == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if ((wolfpsa_check_word32_length(secret_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(label_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(context_length) != PSA_SUCCESS) ||
        (wolfpsa_check_word32_length(output_length) != PSA_SUCCESS)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Get hash type */
    ret = psa_tls13_get_hash_type(alg, &hashType);
    if (ret != 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    
    /* Perform TLS 1.3 HKDF Expand Label operation */
    ret = wc_Tls13_HKDF_Expand_Label(
        output, (word32)output_length,
        secret, (word32)secret_length,
        NULL, 0,  /* protocol */
        label, (word32)label_length,
        context, (word32)context_length,
        hashType
    );
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE && WOLFSSL_TLS13 */
