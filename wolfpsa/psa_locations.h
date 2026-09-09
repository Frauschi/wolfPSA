/* psa_locations.h
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
 * Vendor key locations wolfPSA defines.
 *
 * A key at one of these locations is held by hardware rather than by this
 * library; what wolfPSA stores for it is a reference only the owning driver
 * understands. The values are defined unconditionally so an application can
 * name a location without knowing which drivers the build compiled in - a
 * location with no driver behind it is reported as unsupported at run time.
 *
 * There is no cross-implementation registry to draw these from. mbedTLS
 * assigns a value per driver in each driver's own description file, and NXP's
 * els_pkc PSA driver never compares the value at all: anything that is not
 * local storage goes to its Oracle hook. So wolfPSA picks its own, inside the
 * vendor range the PSA Crypto specification reserves for implementations.
 */

#ifndef WOLFPSA_PSA_LOCATIONS_H
#define WOLFPSA_PSA_LOCATIONS_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <psa/crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NXP EdgeLock (ELS) key store. The material stored for such a key is exactly
 * the id blob the wolfCrypt crypto callback port defines, so TLS and PSA share
 * one encoding. */
#define PSA_KEY_LOCATION_ELS_PKC \
    ((psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x000045))

/* NXP's els_pkc PSA driver calls the same hardware this, so an application
 * ported from it keeps its own constant. Recognised as an alias for
 * PSA_KEY_LOCATION_ELS_PKC, never produced by wolfPSA. */
#ifndef PSA_KEY_LOCATION_EXTERNAL_STORAGE
#define PSA_KEY_LOCATION_EXTERNAL_STORAGE \
    ((psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x000000))
#endif

/* The software stand-in built only for wolfPSA's own tests, so no production
 * build answers to it. */
#define PSA_KEY_LOCATION_WOLFPSA_TEST \
    ((psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x00FFFF))

#ifdef __cplusplus
}
#endif

#endif /* WOLFPSA_PSA_LOCATIONS_H */
