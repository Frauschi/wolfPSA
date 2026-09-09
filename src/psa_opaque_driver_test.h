/* psa_opaque_driver_test.h
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

#ifndef WOLFPSA_OPAQUE_DRIVER_TEST_H
#define WOLFPSA_OPAQUE_DRIVER_TEST_H

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include "psa_opaque_driver.h"

#ifdef WOLFPSA_TEST_OPAQUE_DRIVER

#ifdef __cplusplus
extern "C" {
#endif

extern const wolfpsa_opaque_driver wolfpsa_opaque_driver_test;

/* Counts the ops the driver actually served, so a test can assert the key went
 * through the driver rather than only that the answer was right. */
extern unsigned long wolfpsa_test_driver_hits;

void wolfpsa_test_driver_reset(void);
size_t wolfpsa_test_driver_slots_used(void);

/* Place key material in the driver as if the hardware had been provisioned,
 * and hand back the reference to import as the PSA key. */
psa_status_t wolfpsa_test_driver_inject(const psa_key_attributes_t* attributes,
                                        const uint8_t* key, size_t key_length,
                                        uint8_t* key_data,
                                        size_t key_data_size,
                                        size_t* key_data_length);

#ifdef __cplusplus
}
#endif

#endif /* WOLFPSA_TEST_OPAQUE_DRIVER */

#endif /* WOLFPSA_OPAQUE_DRIVER_TEST_H */
