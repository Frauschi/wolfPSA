/* psa_random.c
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
#include <wolfpsa/psa_engine.h>
#include <wolfpsa/psa_random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/mem_track.h>
#include <wolfssl/wolfcrypt/random.h>

/* Generate random bytes */
psa_status_t psa_generate_random(uint8_t *output, size_t output_size)
{
    int ret;
    WC_RNG rng;
    
    if (output == NULL && output_size > 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    
    /* Initialize the RNG */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    /* Generate random bytes */
    ret = wc_RNG_GenerateBlock(&rng, output, (word32)output_size);
    
    /* Free the RNG */
    wc_FreeRng(&rng);
    
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }
    
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
