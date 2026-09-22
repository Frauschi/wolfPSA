/* psa_kdf_psk_to_ms_size_test.c
 *
 * Regression: PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE is 128 bytes, but neither
 * the input path nor the premaster serialization enforced it. A 129-byte
 * PSK was accepted, and a component over 65535 bytes was serialized with
 * a wrapped 16-bit length even though all bytes were copied into the
 * premaster secret.
 *
 * The input validator now rejects a SECRET longer than
 * PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE and an OTHER_SECRET longer than
 * UINT16_MAX, and the output path independently rejects either premaster
 * component that would wrap its 16-bit length field.
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

#include <psa/crypto.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s: status 0x%08x want 0x%08x\n", label,
               (unsigned)status, (unsigned)expected);
        failures++;
    }
    return (status == expected) ? 0 : 1;
}

static psa_status_t setup_psk_op(psa_key_derivation_operation_t *op)
{
    return psa_key_derivation_setup(op,
                                    PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256));
}

/* The reported bug: a PSK longer than the advertised 128-byte maximum was
 * accepted. */
static int test_rejects_oversized_psk(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static uint8_t psk[129];
    uint8_t seed[32];
    int ret = 0;

    memset(psk, 0x11, sizeof(psk));
    memset(seed, 0x22, sizeof(seed));

    ret |= expect_status("setup", setup_psk_op(&op), PSA_SUCCESS);
    ret |= expect_status("set seed",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SEED,
                                                        seed,
                                                        sizeof(seed)),
                         PSA_SUCCESS);
    ret |= expect_status("set 129-byte psk",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SECRET,
                                                        psk,
                                                        sizeof(psk)),
                         PSA_ERROR_INVALID_ARGUMENT);
    (void)psa_key_derivation_abort(&op);

    return ret;
}

/* The boundary: exactly 128 bytes must still be accepted. */
static int test_accepts_max_psk(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static uint8_t psk[128];
    uint8_t seed[32];
    uint8_t ms[48];
    int ret = 0;

    memset(psk, 0x33, sizeof(psk));
    memset(seed, 0x44, sizeof(seed));

    ret |= expect_status("setup", setup_psk_op(&op), PSA_SUCCESS);
    ret |= expect_status("set seed",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SEED,
                                                        seed,
                                                        sizeof(seed)),
                         PSA_SUCCESS);
    ret |= expect_status("set 128-byte psk",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SECRET,
                                                        psk,
                                                        sizeof(psk)),
                         PSA_SUCCESS);
    ret |= expect_status("output 48-byte master secret",
                         psa_key_derivation_output_bytes(&op, ms,
                                                         sizeof(ms)),
                         PSA_SUCCESS);
    (void)psa_key_derivation_abort(&op);

    return ret;
}

/* An OTHER_SECRET that would wrap its 16-bit premaster length is rejected. */
static int test_rejects_oversized_other_secret(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static uint8_t other[65536];
    uint8_t psk[16];
    uint8_t seed[32];
    int ret = 0;

    memset(other, 0x55, sizeof(other));
    memset(psk, 0x66, sizeof(psk));
    memset(seed, 0x77, sizeof(seed));

    ret |= expect_status("setup", setup_psk_op(&op), PSA_SUCCESS);
    ret |= expect_status("set seed",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SEED,
                                                        seed,
                                                        sizeof(seed)),
                         PSA_SUCCESS);
    ret |= expect_status("set psk",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_SECRET,
                                                        psk,
                                                        sizeof(psk)),
                         PSA_SUCCESS);
    ret |= expect_status("set 65536-byte other secret",
                         psa_key_derivation_input_bytes(&op,
                                                        PSA_KEY_DERIVATION_INPUT_OTHER_SECRET,
                                                        other,
                                                        sizeof(other)),
                         PSA_ERROR_INVALID_ARGUMENT);
    (void)psa_key_derivation_abort(&op);

    return ret;
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("PSA KDF PSK-TO-MS size test: psa_crypto_init failed\n");
        return 1;
    }

    test_rejects_oversized_psk();
    test_accepts_max_psk();
    test_rejects_oversized_other_secret();

    if (failures != 0) {
        printf("PSA KDF PSK-TO-MS size test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA KDF PSK-TO-MS size test: OK\n");
    return 0;
}
