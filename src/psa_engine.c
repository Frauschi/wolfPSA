/* psa_engine.c
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

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>

/* PSA status code to wolfCrypt error code conversion */
int psa_status_to_wc_error(psa_status_t status)
{
    int ret;

    switch (status) {
        case PSA_SUCCESS:
            ret = 0;
            break;
        case PSA_ERROR_NOT_SUPPORTED:
            ret = NOT_COMPILED_IN;
            break;
        case PSA_ERROR_INVALID_ARGUMENT:
            ret = BAD_FUNC_ARG;
            break;
        case PSA_ERROR_BUFFER_TOO_SMALL:
            ret = BUFFER_E;
            break;
        case PSA_ERROR_INSUFFICIENT_MEMORY:
            ret = MEMORY_E;
            break;
        case PSA_ERROR_COMMUNICATION_FAILURE:
        case PSA_ERROR_HARDWARE_FAILURE:
            ret = WC_HW_E;
            break;
        case PSA_ERROR_CORRUPTION_DETECTED:
            ret = SIG_VERIFY_E;
            break;
        case PSA_ERROR_INSUFFICIENT_ENTROPY:
            ret = RNG_FAILURE_E;
            break;
        case PSA_ERROR_INVALID_SIGNATURE:
            ret = SIG_VERIFY_E;
            break;
        case PSA_ERROR_INVALID_PADDING:
            ret = BAD_PADDING_E;
            break;
        case PSA_ERROR_INSUFFICIENT_DATA:
            ret = BUFFER_E;
            break;
        case PSA_ERROR_INVALID_HANDLE:
            ret = BAD_FUNC_ARG;
            break;
        case PSA_ERROR_BAD_STATE:
            ret = BAD_STATE_E;
            break;
        default:
            ret = WC_FAILURE;
            break;
    }

    return ret;
}

/* wolfCrypt error code to PSA status code conversion */
psa_status_t wc_error_to_psa_status(int ret)
{
    psa_status_t status;

    if (ret == 0) {
        return PSA_SUCCESS;
    }

    switch (ret) {
        case NOT_COMPILED_IN:
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        case BAD_FUNC_ARG:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case ECC_BAD_ARG_E:
        case ECC_CURVE_OID_E:
        case ECC_PRIV_KEY_E:
        case ECC_OUT_OF_RANGE_E:
        case ECC_PRIVATEONLY_E:
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
        case BUFFER_E:
            status = PSA_ERROR_BUFFER_TOO_SMALL;
            break;
        case MEMORY_E:
            status = PSA_ERROR_INSUFFICIENT_MEMORY;
            break;
        case WC_HW_E:
            status = PSA_ERROR_HARDWARE_FAILURE;
            break;
        case SIG_VERIFY_E:
            status = PSA_ERROR_INVALID_SIGNATURE;
            break;
        case AES_GCM_AUTH_E:
        case AES_CCM_AUTH_E:
        case AES_EAX_AUTH_E:
        case AES_SIV_AUTH_E:
        case MAC_CMP_FAILED_E:
            status = PSA_ERROR_INVALID_SIGNATURE;
            break;
        case RNG_FAILURE_E:
            status = PSA_ERROR_INSUFFICIENT_ENTROPY;
            break;
        case BAD_PADDING_E:
            status = PSA_ERROR_INVALID_PADDING;
            break;
        case BAD_STATE_E:
            status = PSA_ERROR_BAD_STATE;
            break;
        default:
            status = PSA_ERROR_GENERIC_ERROR;
            break;
    }

    return status;
}

/* Check if algorithm is supported */
psa_status_t psa_check_alg_supported(psa_algorithm_t alg)
{
    /* Check if the algorithm is a cipher algorithm */
    if (PSA_ALG_IS_CIPHER(alg)) {
        switch (alg) {
            case PSA_ALG_ECB_NO_PADDING:
            #if defined(HAVE_AES_ECB)
                return PSA_SUCCESS;
            #else
                return PSA_ERROR_NOT_SUPPORTED;
            #endif

            case PSA_ALG_CBC_NO_PADDING:
            #if defined(HAVE_AES_CBC)
                return PSA_SUCCESS;
            #else
                return PSA_ERROR_NOT_SUPPORTED;
            #endif

            case PSA_ALG_CBC_PKCS7:
            #if defined(HAVE_AES_CBC) && defined(WOLFSSL_AES_PADDING)
                return PSA_SUCCESS;
            #else
                return PSA_ERROR_NOT_SUPPORTED;
            #endif

            case PSA_ALG_CTR:
            #if defined(WOLFSSL_AES_COUNTER)
                return PSA_SUCCESS;
            #else
                return PSA_ERROR_NOT_SUPPORTED;
            #endif

            case PSA_ALG_CFB:
            #if defined(WOLFSSL_AES_CFB)
                return PSA_SUCCESS;
            #else
                return PSA_ERROR_NOT_SUPPORTED;
            #endif

            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/* Check if key type is supported */
psa_status_t psa_check_key_type_supported(psa_key_type_t type)
{
    switch (type) {
        case PSA_KEY_TYPE_AES:
        #ifndef NO_AES
            return PSA_SUCCESS;
        #else
            return PSA_ERROR_NOT_SUPPORTED;
        #endif

        case PSA_KEY_TYPE_DES:
        #ifndef NO_DES3
            return PSA_SUCCESS;
        #else
            return PSA_ERROR_NOT_SUPPORTED;
        #endif

        case PSA_KEY_TYPE_HMAC:
        #ifndef NO_HMAC
            return PSA_SUCCESS;
        #else
            return PSA_ERROR_NOT_SUPPORTED;
        #endif

        case PSA_KEY_TYPE_RAW_DATA:
            return PSA_SUCCESS;

        case PSA_KEY_TYPE_CHACHA20:
        #if defined(HAVE_CHACHA)
            return PSA_SUCCESS;
        #else
            return PSA_ERROR_NOT_SUPPORTED;
        #endif

        default:
            break;
    }

    if (PSA_KEY_TYPE_IS_RSA(type)) {
    #ifndef NO_RSA
        return PSA_SUCCESS;
    #else
        return PSA_ERROR_NOT_SUPPORTED;
    #endif
    }

    if (PSA_KEY_TYPE_IS_ECC(type)) {
    #ifdef HAVE_ECC
        return PSA_SUCCESS;
    #else
        return PSA_ERROR_NOT_SUPPORTED;
    #endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

/* Check if key size is valid for the given key type */
psa_status_t psa_check_key_size_valid(psa_key_type_t type, size_t bits)
{
    extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);

    switch (type) {
        case PSA_KEY_TYPE_AES:
        #ifndef NO_AES
            if (bits == 128 || bits == 192 || bits == 256) {
                return PSA_SUCCESS;
            }
            return PSA_ERROR_INVALID_ARGUMENT;
        #else
            return PSA_ERROR_NOT_SUPPORTED;
        #endif

        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_RAW_DATA:
            if (bits > 0) {
                return PSA_SUCCESS;
            }
            return PSA_ERROR_INVALID_ARGUMENT;

        case PSA_KEY_TYPE_CHACHA20:
            if (bits == 256) {
                return PSA_SUCCESS;
            }
            return PSA_ERROR_INVALID_ARGUMENT;

        default:
            break;
    }

    if (PSA_KEY_TYPE_IS_RSA(type)) {
#ifndef NO_RSA
        if (bits >= 2048 && (bits % 8u) == 0 &&
            bits <= PSA_VENDOR_RSA_MAX_KEY_BITS) {
            return PSA_SUCCESS;
        }
        return PSA_ERROR_INVALID_ARGUMENT;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    if (PSA_KEY_TYPE_IS_ECC(type)) {
#ifdef HAVE_ECC
        if (wc_psa_get_ecc_curve_id(type, bits) != ECC_CURVE_INVALID) {
            return PSA_SUCCESS;
        }
        return PSA_ERROR_NOT_SUPPORTED;
#else
        return PSA_ERROR_NOT_SUPPORTED;
#endif
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

#endif /* WOLFSSL_PSA_ENGINE */
