/* psa_opaque_driver.c
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

#include "psa_opaque_driver.h"
#include "psa_opaque_driver_els_pkc.h"
#include "psa_opaque_driver_test.h"

/* NULL-terminated so the array stays valid with no driver compiled in. Each
 * driver's own header decides whether it is here. */
static const wolfpsa_opaque_driver* const wolfpsa_opaque_drivers[] = {
#ifdef WOLFPSA_HAVE_ELS_KEYSTORE
    &wolfpsa_opaque_driver_els_pkc,
#endif
#ifdef WOLFPSA_TEST_OPAQUE_DRIVER
    &wolfpsa_opaque_driver_test,
#endif
    NULL
};

const wolfpsa_opaque_driver* wolfpsa_opaque_driver_find(psa_key_lifetime_t
                                                        lifetime)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);
    size_t i;

    if (location == PSA_KEY_LOCATION_LOCAL_STORAGE) {
        return NULL;
    }

    for (i = 0; wolfpsa_opaque_drivers[i] != NULL; i++) {
        if (wolfpsa_opaque_drivers[i]->location == location ||
            wolfpsa_opaque_drivers[i]->location_alias == location) {
            return wolfpsa_opaque_drivers[i];
        }
    }

    return NULL;
}

psa_status_t wolfpsa_opaque_driver_reject(psa_key_lifetime_t lifetime)
{
    if (wolfpsa_opaque_driver_find(lifetime) != NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

#endif /* WOLFSSL_PSA_ENGINE */
