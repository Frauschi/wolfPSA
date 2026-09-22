/* psa_kdf_expand_context_test.c
 *
 * Regression: the HKDF-Expand step validator rejected SALT but let
 * every other unrecognized step fall through to PSA_SUCCESS. CONTEXT
 * was accepted and stored, while the HKDF-Expand backend consumes only
 * SECRET and INFO, so a derivation with a CONTEXT input silently
 * produced the same output as one without it.
 *
 * The HKDF-Expand validator is now a positive whitelist: SECRET
 * (exactly one hash length, first) and INFO (after SECRET) are
 * accepted, and every other step, including CONTEXT, is rejected with
 * PSA_ERROR_INVALID_ARGUMENT.
 *
 * The happy path is checked against RFC 5869 test case 1 (HKDF-SHA256
 * expand: PRK as the secret, the RFC info, 42-byte OKM).
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

/* RFC 5869 test case 1, HKDF-SHA256. */
static const uint8_t rfc5869_prk[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};
static const uint8_t rfc5869_info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9
};
static const uint8_t rfc5869_okm[42] = {
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
    0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
    0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
    0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
    0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
    0x58, 0x65
};

/* Each rejected step gets its own operation: PSA puts an operation into an
 * error state when an input is refused, so nothing may be asserted about
 * reusing it afterwards. */
static int test_expand_rejects_step(const char *label,
                                    psa_key_derivation_step_t step)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t status;
    int ret = 0;

    status = psa_key_derivation_setup(&op,
                                      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ret |= expect_status("setup", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, rfc5869_prk,
        sizeof(rfc5869_prk));
    ret |= expect_status("set secret", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(&op, step, rfc5869_info,
                                            sizeof(rfc5869_info));
    ret |= expect_status(label, status, PSA_ERROR_INVALID_ARGUMENT);

    (void)psa_key_derivation_abort(&op);

    return ret;
}

static int test_expand_rejects_unconsumed_steps(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[16];
    psa_status_t status;
    int ret = 0;

    /* The reported bug: CONTEXT was accepted and ignored. The whitelist
     * rejects every remaining unconsumed step too. */
    ret |= test_expand_rejects_step("set context",
                                    PSA_KEY_DERIVATION_INPUT_CONTEXT);
    ret |= test_expand_rejects_step("set seed",
                                    PSA_KEY_DERIVATION_INPUT_SEED);
    ret |= test_expand_rejects_step("set label",
                                    PSA_KEY_DERIVATION_INPUT_LABEL);

    /* INFO is the one optional step HKDF-Expand does consume. */
    status = psa_key_derivation_setup(&op,
                                      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ret |= expect_status("setup", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, rfc5869_prk,
        sizeof(rfc5869_prk));
    ret |= expect_status("set secret", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_INFO, rfc5869_info,
        sizeof(rfc5869_info));
    ret |= expect_status("set info", status, PSA_SUCCESS);

    status = psa_key_derivation_output_bytes(&op, out, sizeof(out));
    ret |= expect_status("output", status, PSA_SUCCESS);
    (void)psa_key_derivation_abort(&op);

    return ret;
}

static int test_expand_info_before_secret(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t status;
    int ret = 0;

    status = psa_key_derivation_setup(&op,
                                      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ret |= expect_status("setup", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_INFO, rfc5869_info,
        sizeof(rfc5869_info));
    ret |= expect_status("set info first", status, PSA_ERROR_BAD_STATE);

    (void)psa_key_derivation_abort(&op);

    return ret;
}

static int test_expand_rfc5869_vector(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t okm[42];
    psa_status_t status;
    int ret = 0;

    status = psa_key_derivation_setup(&op,
                                      PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    ret |= expect_status("setup", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, rfc5869_prk,
        sizeof(rfc5869_prk));
    ret |= expect_status("set secret", status, PSA_SUCCESS);

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_INFO, rfc5869_info,
        sizeof(rfc5869_info));
    ret |= expect_status("set info", status, PSA_SUCCESS);

    /* The full 42 bytes of RFC 5869 A.1, so T(2) is covered too. */
    status = psa_key_derivation_output_bytes(&op, okm, sizeof(okm));
    ret |= expect_status("output", status, PSA_SUCCESS);
    if (ret == 0 && memcmp(okm, rfc5869_okm, sizeof(okm)) != 0) {
        printf("FAIL rfc5869 okm mismatch\n");
        failures++;
    }
    (void)psa_key_derivation_abort(&op);

    return ret;
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("PSA KDF expand context test: psa_crypto_init failed\n");
        return 1;
    }

    test_expand_rejects_unconsumed_steps();
    test_expand_info_before_secret();
    test_expand_rfc5869_vector();

    if (failures != 0) {
        printf("PSA KDF expand context test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA KDF expand context test: OK\n");
    return 0;
}
