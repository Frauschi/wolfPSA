/* psa_pq.c
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
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>

/* Check if a key type is a post-quantum key type */
psa_status_t psa_pq_check_key_type_supported(psa_key_type_t type)
{
    switch (type) {
#if defined(WOLFSSL_HAVE_MLKEM)
        case PSA_KEY_TYPE_ML_KEM_KEY_PAIR:
        case PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY:
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_MLDSA)
        case PSA_KEY_TYPE_ML_DSA_KEY_PAIR:
        case PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY:
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_LMS) && defined(PSA_KEY_TYPE_LMS_KEY_PAIR)
        case PSA_KEY_TYPE_LMS_KEY_PAIR:
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_LMS) && defined(PSA_KEY_TYPE_LMS_PUBLIC_KEY)
        case PSA_KEY_TYPE_LMS_PUBLIC_KEY:
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_XMSS) && defined(PSA_KEY_TYPE_XMSS_KEY_PAIR)
        case PSA_KEY_TYPE_XMSS_KEY_PAIR:
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_XMSS) && defined(PSA_KEY_TYPE_XMSS_PUBLIC_KEY)
        case PSA_KEY_TYPE_XMSS_PUBLIC_KEY:
            return PSA_SUCCESS;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

/* Check if a key size is valid for the given post-quantum key type */
psa_status_t psa_pq_check_key_size_valid(psa_key_type_t type, size_t bits)
{
    (void)type;
    (void)bits;

    switch (type) {
#if defined(WOLFSSL_HAVE_MLKEM)
        case PSA_KEY_TYPE_ML_KEM_KEY_PAIR:
        case PSA_KEY_TYPE_ML_KEM_PUBLIC_KEY:
            /* ML-KEM key sizes: 512, 768, 1024 */
            if (bits == 512 || bits == 768 || bits == 1024) {
                return PSA_SUCCESS;
            }
            return PSA_ERROR_INVALID_ARGUMENT;
#endif
#if defined(WOLFSSL_HAVE_MLDSA)
        case PSA_KEY_TYPE_ML_DSA_KEY_PAIR:
        case PSA_KEY_TYPE_ML_DSA_PUBLIC_KEY:
            /* ML-DSA key sizes: 2, 3, 5 (security levels) */
            if (bits == 2 || bits == 3 || bits == 5) {
                return PSA_SUCCESS;
            }
            return PSA_ERROR_INVALID_ARGUMENT;
#endif
#if defined(WOLFSSL_HAVE_LMS) && defined(PSA_KEY_TYPE_LMS_KEY_PAIR)
        case PSA_KEY_TYPE_LMS_KEY_PAIR:
            /* LMS doesn't have specific key sizes in the same way */
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_LMS) && defined(PSA_KEY_TYPE_LMS_PUBLIC_KEY)
        case PSA_KEY_TYPE_LMS_PUBLIC_KEY:
            /* LMS doesn't have specific key sizes in the same way */
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_XMSS) && defined(PSA_KEY_TYPE_XMSS_KEY_PAIR)
        case PSA_KEY_TYPE_XMSS_KEY_PAIR:
            /* XMSS doesn't have specific key sizes in the same way */
            return PSA_SUCCESS;
#endif
#if defined(WOLFSSL_HAVE_XMSS) && defined(PSA_KEY_TYPE_XMSS_PUBLIC_KEY)
        case PSA_KEY_TYPE_XMSS_PUBLIC_KEY:
            /* XMSS doesn't have specific key sizes in the same way */
            return PSA_SUCCESS;
#endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

#endif /* WOLFSSL_PSA_ENGINE */
