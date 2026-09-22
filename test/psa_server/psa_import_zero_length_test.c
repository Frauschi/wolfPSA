/* psa_import_zero_length_test.c
 *
 * Regression: psa_import_key() accepted a zero-length blob for persistent
 * RSA, ECC, and DH keys when the caller supplied a nonzero bit count. Those
 * types have no per-type data_length check, and the bits-inference path (the
 * only place a zero length was rejected) is skipped when bits are supplied.
 * The persistent path then serialized and stored the zero length and returned
 * success; the stored record was rejected on read, leaving a persistent key
 * that occupied its identifier but could not be used until destroyed.
 *
 * A zero-length blob is not a valid representation of any key type, so the
 * import now rejects data_length == 0 up front with PSA_ERROR_INVALID_ARGUMENT.
 * The test covers RSA and ECC (DH shares the same unchecked path but is
 * disabled in this build).
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

#include <wolfpsa/psa/crypto.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define WOLFPSA_TEST_PERSISTENT_ID 0x0000a55a

static int failures;

/* Zero-length blob with a nonzero declared bit count must be rejected for
 * each asymmetric type that lacks a per-type length check. */
static void test_zero_length_rejected(psa_key_type_t type,
                                      psa_key_bits_t bits,
                                      psa_key_id_t key_id,
                                      const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t out_id = PSA_KEY_ID_NULL;
    uint8_t dummy = 0;
    psa_status_t status;

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, key_id);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_NONE);

    status = psa_import_key(&attrs, &dummy, 0, &out_id);
    if (status != PSA_ERROR_INVALID_ARGUMENT) {
        printf("FAIL %s: zero-length import status=%d expected=%d\n", name,
               (int)status, (int)PSA_ERROR_INVALID_ARGUMENT);
        failures++;
        return;
    }
    (void)psa_destroy_key(key_id);
}

/* A valid import must still succeed, so the zero-length guard does not
 * over-reject the normal path. */
static void test_valid_import_still_works(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    /* 32-byte SECP-R1 secret key (P-256). */
    static const uint8_t priv[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    psa_status_t status;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, WOLFPSA_TEST_PERSISTENT_ID);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_NONE);

    status = psa_import_key(&attrs, priv, sizeof(priv), &key_id);
    if (status != PSA_SUCCESS) {
        printf("FAIL valid-import: status=%d expected=%d\n", (int)status,
               (int)PSA_SUCCESS);
        failures++;
        return;
    }
    (void)psa_destroy_key(WOLFPSA_TEST_PERSISTENT_ID);
}

int main(void)
{
    /* Point the persistent store at a fresh directory so the test is
     * independent of the working directory and any leftover records. The
     * library reads WOLFPSA_TOKEN_PATH on every store operation. Left in
     * /tmp on a failing run; removed on success (the dir is then empty). */
    char dir[] = "/tmp/wolfpsa_import_zero_XXXXXX";
    psa_status_t init;

    if (mkdtemp(dir) == NULL) {
        printf("psa_import_zero_length_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("psa_import_zero_length_test: setenv failed\n");
        (void)rmdir(dir);
        return 1;
    }

    init = psa_crypto_init();
    if (init != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)init);
        return 1;
    }

    test_zero_length_rejected(
        PSA_KEY_TYPE_RSA_KEY_PAIR, 2048, 0x0000a551, "RSA");
    test_zero_length_rejected(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256, 0x0000a552,
        "ECC");
    test_valid_import_still_works();

    (void)rmdir(dir);

    if (failures != 0) {
        printf("PSA import zero-length test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA import zero-length test: OK\n");
    return 0;
}
