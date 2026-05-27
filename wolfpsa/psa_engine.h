/* psa_engine.h
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

/**
 * Platform Security Architecture (PSA) Engine header
 *
 * If WOLFSSL_PSA_ENGINE is defined, wolfSSL provides an implementation of the
 * PSA Crypto API that calls wolfCrypt APIs.
 *
 */

#ifndef WOLFSSL_PSA_ENGINE_H
#define WOLFSSL_PSA_ENGINE_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE)

#include <psa/crypto.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/visibility.h>

#ifndef NO_AES
#include <wolfssl/wolfcrypt/aes.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* wolfCrypt error code to PSA status code conversion */
WOLFSSL_LOCAL psa_status_t wc_error_to_psa_status(int ret);

/* Default wolfCrypt devId threaded through wolfPSA's internal wc_*Init()
 * calls. Defaults to INVALID_DEVID so that operations execute locally.
 * Set to a registered crypto_cb devId (e.g. via wc_CryptoCb_RegisterDevice)
 * to route every wolfPSA-issued wolfCrypt call through that callback —
 * this is the integration hook for crypto offload backends such as
 * wolfHSM or a hardware accelerator. Safe to call before psa_crypto_init().
 *
 * Threading: the default devId is held in a process-global variable read
 * by every wolfPSA-internal wc_*Init() invocation. Callers must set it
 * during single-threaded initialisation (before any PSA operation is
 * issued) or otherwise serialise the setter with external synchronisation;
 * concurrent calls to wolfPSA_SetDefaultDevID() while PSA operations are
 * in flight are not supported.
 *
 * Returns 0 on success. */
WOLFSSL_API int wolfPSA_SetDefaultDevID(int devId);

/* Returns the devId previously set with wolfPSA_SetDefaultDevID() or
 * INVALID_DEVID if none has been set. */
WOLFSSL_API int wolfPSA_GetDefaultDevID(void);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_PSA_ENGINE */
#endif /* WOLFSSL_PSA_ENGINE_H */
