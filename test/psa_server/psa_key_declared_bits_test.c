/* psa_key_declared_bits_test.c
 *
 * Regression test: psa_import_key() validated declared bits
 * against data length for AES/DES/ChaCha20/XChaCha20 but not for the
 * other raw byte-string key types (HMAC, RAW_DATA, DERIVE, PASSWORD,
 * PASSWORD_HASH, PEPPER), so e.g. one byte imported as a 256-bit HMAC
 * key succeeded, and zero-size imports were stored (persistent lifetime)
 * or mis-recorded.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <psa/crypto.h>

static int test_import(psa_key_type_t type, size_t bits, const uint8_t* data,
                       size_t len, psa_key_bits_t expected_bits,
                       psa_status_t expected_status, int persistent,
                       const char* label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    psa_set_key_type(&attrs, type);
    if (bits != 0) {
        psa_set_key_bits(&attrs, bits);
    }
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    if (persistent) {
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
        psa_set_key_id(&attrs, PSA_KEY_ID_USER_MIN + 1);
    }
    else {
        psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);
    }

    st = psa_import_key(&attrs, data, len, &key_id);
    if (st != expected_status) {
        printf("FAIL %s status=%d expected=%d\n", label, (int)st,
               (int)expected_status);
        goto out;
    }
    if (expected_status != PSA_SUCCESS) {
        ok = 1;
        goto out;
    }

    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s attrs status=%d\n", label, (int)st);
        goto destroy;
    }

    if (psa_get_key_bits(&got) != expected_bits) {
        printf("FAIL %s bits=%u expected=%u\n", label,
               (unsigned)psa_get_key_bits(&got),
               (unsigned)expected_bits);
        goto destroy;
    }

    ok = 1;

destroy:
    (void)psa_destroy_key(key_id);

out:
    return ok ? 0 : 1;
}

int main(void)
{
    uint8_t one[1] = { 0x42 };
    uint8_t four[4] = { 0x01, 0x02, 0x03, 0x04 };
    uint8_t two[2] = { 0xAA, 0xBB };
    char store_dir[] = "/tmp/wolfpsa_declared_bits_XXXXXX";
    int rc = 0;

    if (mkdtemp(store_dir) == NULL) {
        printf("FAIL mkdtemp\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("FAIL setenv\n");
        return 1;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    /* Declared bits must equal data length in bits for byte-string keys. */
    rc |= test_import(PSA_KEY_TYPE_HMAC, 256, one, 1, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "hmac-1B-256b");
    rc |= test_import(PSA_KEY_TYPE_RAW_DATA, 32, one, 1, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "raw-1B-32b");
    rc |= test_import(PSA_KEY_TYPE_DERIVE, 64, one, 1, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "derive-1B-64b");
    rc |= test_import(PSA_KEY_TYPE_PASSWORD, 128, two, 2, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "pwd-2B-128b");
    rc |= test_import(PSA_KEY_TYPE_PASSWORD_HASH, 64, two, 2, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "pwdhash-2B-64b");
    rc |= test_import(PSA_KEY_TYPE_PEPPER, 16, four, 4, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 0, "pepper-4B-16b");

    /* Consistent explicit bits and inference still work. */
    rc |= test_import(PSA_KEY_TYPE_HMAC, 8, one, 1, 8, PSA_SUCCESS, 0,
                      "hmac-1B-8b");
    rc |= test_import(PSA_KEY_TYPE_RAW_DATA, 0, four, 4, 32, PSA_SUCCESS, 0,
                      "raw-4B-infer");
    rc |= test_import(PSA_KEY_TYPE_PASSWORD, 16, two, 2, 16, PSA_SUCCESS, 0,
                      "pwd-2B-16b");

    /* Zero-size imports must be rejected (persistent lifetime, where the
     * pre-fix code stored them). */
    rc |= test_import(PSA_KEY_TYPE_RAW_DATA, 0, one, 0, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 1, "raw-0B-persist");
    rc |= test_import(PSA_KEY_TYPE_HMAC, 0, one, 0, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 1, "hmac-0B-persist");
    rc |= test_import(PSA_KEY_TYPE_PEPPER, 8, one, 0, 0,
                      PSA_ERROR_INVALID_ARGUMENT, 1, "pepper-0B-persist");

    if (rc != 0) {
        printf("PSA unstructbits test: FAIL\n");
        return 1;
    }

    printf("PSA unstructbits test: OK\n");
    return 0;
}
