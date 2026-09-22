/* psa_ecc_bit_inference_test.c
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
#include <string.h>

#include <wolfpsa/psa/crypto.h>

static int check_inferred_bits(psa_key_type_t key_type, const uint8_t* key_data,
                               size_t key_data_len, psa_key_bits_t expected_bits,
                               const char* label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, key_type);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);

    st = psa_import_key(&attrs, key_data, key_data_len, &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s import status=%d\n", label, (int)st);
        return 1;
    }

    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s attrs status=%d\n", label, (int)st);
        (void)psa_destroy_key(key_id);
        return 1;
    }

    if (psa_get_key_bits(&got) != expected_bits) {
        printf("FAIL %s bits=%u expected=%u\n", label,
               (unsigned)psa_get_key_bits(&got), (unsigned)expected_bits);
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    return 0;
}

static int test_public_key_bits(void)
{
    uint8_t pub[133];

    memset(pub, 0, sizeof(pub));
    pub[0] = 0x04;

    return check_inferred_bits(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1),
        pub, sizeof(pub), 521, "secp521r1 public");
}

static int test_private_key_bits(void)
{
    uint8_t priv[66];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    memset(priv, 0, sizeof(priv));
    priv[sizeof(priv) - 1] = 1;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);

    st = psa_import_key(&attrs, priv, sizeof(priv), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL private import status=%d\n", (int)st);
        return 1;
    }

    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL private attrs status=%d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return 1;
    }

    if (psa_get_key_bits(&got) != 521) {
        printf("FAIL private bits=%u expected=521\n",
               (unsigned)psa_get_key_bits(&got));
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    return 0;
}

static int test_raw_public_key_bits(void)
{
    uint8_t x25519_pub[32];
    uint8_t ed25519_pub[32];
    uint8_t ed448_pub[57];

    memset(x25519_pub, 0xA5, sizeof(x25519_pub));
    memset(ed25519_pub, 0x5A, sizeof(ed25519_pub));
    memset(ed448_pub, 0x3C, sizeof(ed448_pub));

    if (check_inferred_bits(
            PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY),
            x25519_pub, sizeof(x25519_pub), 255, "x25519 public") != 0) {
        return 1;
    }

    if (check_inferred_bits(
            PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS),
            ed25519_pub, sizeof(ed25519_pub), 255, "ed25519 public") != 0) {
        return 1;
    }

    return check_inferred_bits(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS),
        ed448_pub, sizeof(ed448_pub), 448, "ed448 public");
}

/* The import-time rejections: each of these encodings used to be stored and
 * only fail later at use. */
static int check_import_rejected(psa_key_type_t key_type, psa_key_bits_t bits,
                                 const uint8_t *data, size_t data_len,
                                 psa_status_t expected, const char *label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attrs, key_type);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    if (bits != 0) {
        psa_set_key_bits(&attrs, bits);
    }

    st = psa_import_key(&attrs, data, data_len, &key_id);
    if (st != expected) {
        printf("FAIL %s: status=%d expected=%d\n", label, (int)st,
               (int)expected);
        if (st == PSA_SUCCESS) {
            (void)psa_destroy_key(key_id);
        }
        return 1;
    }
    return 0;
}

static int test_import_rejections(void)
{
    uint8_t p256_pub[65];
    uint8_t p256_even[64];
    uint8_t buf57[57];
    uint8_t buf56[56];
    uint8_t scalar32[32];
    int ret = 0;

    memset(p256_pub, 0x11, sizeof(p256_pub));
    p256_pub[0] = 0x04;
    memset(p256_even, 0x11, sizeof(p256_even));
    memset(buf57, 0x22, sizeof(buf57));
    memset(buf56, 0x33, sizeof(buf56));
    memset(scalar32, 0x44, sizeof(scalar32));

    /* A compressed (0x02-prefixed) point: PSA mandates the uncompressed
     * SEC 1 2.3.3 form. */
    p256_pub[0] = 0x02;
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), 256,
        p256_pub, sizeof(p256_pub), PSA_ERROR_INVALID_ARGUMENT,
        "p256 public 0x02 prefix");
    p256_pub[0] = 0x04;

    /* An even length cannot be 1 + 2 * coordinate_size. */
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), 256,
        p256_even, sizeof(p256_even), PSA_ERROR_INVALID_ARGUMENT,
        "p256 public even length");

    /* bits and data describe different curves. */
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 384,
        scalar32, sizeof(scalar32), PSA_ERROR_INVALID_ARGUMENT,
        "secp_r1 bits=384 with 32-byte scalar");

    /* X448 is 56 bytes (RFC 7748 s.5), Ed448 is 57 (RFC 8032 s.5.2.5): the
     * two 448-bit families do not share an encoding length. */
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_MONTGOMERY), 448,
        buf57, sizeof(buf57), PSA_ERROR_INVALID_ARGUMENT,
        "x448 public 57 bytes");
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS), 448,
        buf56, sizeof(buf56), PSA_ERROR_INVALID_ARGUMENT,
        "ed448 public 56 bytes");

    /* A self-consistent request for a curve wolfPSA has no entry for is
     * NOT_SUPPORTED, not INVALID_ARGUMENT. */
    ret |= check_import_rejected(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 384,
        buf56, 48, PSA_ERROR_NOT_SUPPORTED,
        "secp_k1 384 (unsupported curve)");

    return ret;
}

int main(void)
{
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    if (test_public_key_bits() != 0) {
        return 1;
    }
    if (test_private_key_bits() != 0) {
        return 1;
    }
    if (test_raw_public_key_bits() != 0) {
        return 1;
    }
    if (test_import_rejections() != 0) {
        return 1;
    }

    printf("PSA ECC bit inference test: OK\n");
    return 0;
}
