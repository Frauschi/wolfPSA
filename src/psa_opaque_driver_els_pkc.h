/* psa_opaque_driver_els_pkc.h
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

#ifndef WOLFPSA_OPAQUE_DRIVER_ELS_PKC_H
#define WOLFPSA_OPAQUE_DRIVER_ELS_PKC_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include "psa_opaque_driver.h"

/* The EdgeLock driver needs more than WOLFSSL_ELS_PKC promises: reserving and
 * deleting a slot live behind WOLF_CRYPTO_CB_KEYSTORE, and binding one to a
 * wolfCrypt key object behind that key's own algorithm macro. Track the first
 * two here so an ELS build without the extension still compiles, just without
 * the driver. */
#if defined(WOLFSSL_ELS_PKC) && defined(WOLF_CRYPTO_CB_KEYSTORE)
    #define WOLFPSA_HAVE_ELS_KEYSTORE
#endif

#ifdef WOLFPSA_HAVE_ELS_KEYSTORE

#ifdef __cplusplus
extern "C" {
#endif

extern const wolfpsa_opaque_driver wolfpsa_opaque_driver_els_pkc;

#ifdef __cplusplus
}
#endif

#endif /* WOLFPSA_HAVE_ELS_KEYSTORE */

#endif /* WOLFPSA_OPAQUE_DRIVER_ELS_PKC_H */
