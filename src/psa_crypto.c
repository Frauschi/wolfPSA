/* psa_crypto.c
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
#include <wolfssl/wolfcrypt/wc_port.h>

static int g_psa_crypto_initialized = 0;

int wolfPSA_CryptoIsInitialized(void)
{
    return g_psa_crypto_initialized;
}

psa_status_t psa_crypto_init(void)
{
    int ret;

    wolfpsa_trace("psa_crypto_init()");

    if (g_psa_crypto_initialized) {
        return PSA_SUCCESS;
    }

    ret = wolfCrypt_Init();
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    g_psa_crypto_initialized = 1;
    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
