/* psa_ecc_curve_id_test.c
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

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>

#include <wolfpsa/psa/crypto.h>
#include <wolfssl/wolfcrypt/ecc.h>

extern psa_status_t psa_asymmetric_check_key_size_valid(psa_key_type_t type,
                                                        size_t bits);
extern int wc_psa_get_ecc_curve_id(psa_key_type_t type, size_t bits);

static int check_curve(psa_ecc_family_t family, size_t bits, int expected_curve,
                       const char* label)
{
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(family);
    psa_status_t st = psa_asymmetric_check_key_size_valid(type, bits);
    int curve_id = wc_psa_get_ecc_curve_id(type, bits);

    if (st != PSA_SUCCESS) {
        printf("SKIP %s validation unsupported (status=%d)\n", label, (int)st);
        return 0;
    }

    if (curve_id != expected_curve) {
        printf("FAIL %s curve_id=%d expected=%d\n",
               label, curve_id, expected_curve);
        return 1;
    }

    return 0;
}

int main(void)
{
    int failed = 0;

    failed |= check_curve(PSA_ECC_FAMILY_SECP_R1, 192, ECC_SECP192R1,
                          "secp_r1_192");
    failed |= check_curve(PSA_ECC_FAMILY_SECP_R1, 224, ECC_SECP224R1,
                          "secp_r1_224");
    failed |= check_curve(PSA_ECC_FAMILY_SECP_K1, 192, ECC_SECP192K1,
                          "secp_k1_192");
    failed |= check_curve(PSA_ECC_FAMILY_SECP_K1, 224, ECC_SECP224K1,
                          "secp_k1_224");

    if (failed != 0) {
        return 1;
    }

    printf("PSA ECC curve id test: OK\n");
    return 0;
}
