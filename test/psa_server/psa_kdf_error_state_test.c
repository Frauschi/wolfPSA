/* psa_kdf_error_state_test.c
 *
 * Regression test: a failed call on a key-derivation operation must put that
 * operation into an error state, after which every call except
 * psa_key_derivation_abort() reports PSA_ERROR_BAD_STATE. wolfPSA previously
 * returned the validator status and left the operation fully usable, so a
 * caller could ignore a rejected input and keep deriving.
 *
 * Two statuses are deliberately not treated as entering the error state:
 *
 *   PSA_ERROR_INVALID_SIGNATURE  the verify step ran to completion and
 *                                reported a mismatch.
 *   PSA_ERROR_INVALID_HANDLE     the key argument was rejected before the
 *                                operation was touched. The PSA API test
 *                                suite depends on this (arch test c019).
 *
 * psa_key_derivation_get_capacity() stays callable in the error state: it is
 * a read-only query, and arch test c067 reads the capacity back after a
 * verify that failed for insufficient data.
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
        return 1;
    }
    return 0;
}

/* HKDF-SHA256 PRK, RFC 5869 test case 1. */
static const uint8_t prk[32] = {
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
    0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
    0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
};
static const uint8_t info[10] = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9
};

/* Bring an HKDF-Expand operation up to the point where SECRET is set. */
static int setup_expand(psa_key_derivation_operation_t *op)
{
    if (psa_key_derivation_setup(op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)) !=
        PSA_SUCCESS) {
        return 1;
    }
    return psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                          prk, sizeof(prk)) != PSA_SUCCESS;
}

/* A rejected input poisons the operation for every later call. */
static void test_rejected_input_poisons(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[16];
    int ret = 0;

    if (setup_expand(&op) != 0) {
        printf("FAIL poison: setup\n");
        failures++;
        return;
    }

    /* CONTEXT is not consumed by HKDF-Expand. */
    ret |= expect_status("rejected input",
                         psa_key_derivation_input_bytes(
                             &op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                             info, sizeof(info)),
                         PSA_ERROR_INVALID_ARGUMENT);

    /* Everything after it must report BAD_STATE. */
    ret |= expect_status("input after error",
                         psa_key_derivation_input_bytes(
                             &op, PSA_KEY_DERIVATION_INPUT_INFO,
                             info, sizeof(info)),
                         PSA_ERROR_BAD_STATE);
    ret |= expect_status("output after error",
                         psa_key_derivation_output_bytes(&op, out,
                                                         sizeof(out)),
                         PSA_ERROR_BAD_STATE);
    ret |= expect_status("set_capacity after error",
                         psa_key_derivation_set_capacity(&op, 16),
                         PSA_ERROR_BAD_STATE);

    /* abort() is the one call that must still work, and it must release the
     * operation so a fresh setup succeeds on it. */
    ret |= expect_status("abort after error",
                         psa_key_derivation_abort(&op), PSA_SUCCESS);
    ret |= expect_status("reuse after abort",
                         psa_key_derivation_setup(
                             &op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256)),
                         PSA_SUCCESS);
    (void)psa_key_derivation_abort(&op);

    if (ret == 0) {
        printf("PASS rejected input poisons the operation\n");
    }
}

/* get_capacity is a read-only query and stays callable in the error state. */
static void test_get_capacity_exempt(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    size_t capacity = 0;
    int ret = 0;

    if (setup_expand(&op) != 0) {
        printf("FAIL capacity: setup\n");
        failures++;
        return;
    }

    ret |= expect_status("rejected input",
                         psa_key_derivation_input_bytes(
                             &op, PSA_KEY_DERIVATION_INPUT_CONTEXT,
                             info, sizeof(info)),
                         PSA_ERROR_INVALID_ARGUMENT);
    ret |= expect_status("get_capacity in error state",
                         psa_key_derivation_get_capacity(&op, &capacity),
                         PSA_SUCCESS);
    (void)psa_key_derivation_abort(&op);

    if (ret == 0) {
        printf("PASS get_capacity stays callable in the error state\n");
    }
}

/* A verify mismatch is a completed operation reporting "did not match", not
 * a failure of the operation, so it must not poison it. */
static void test_verify_mismatch_does_not_poison(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t wrong[16];
    psa_status_t status;
    int ret = 0;

    memset(wrong, 0xa5, sizeof(wrong));

    if (setup_expand(&op) != 0 ||
        psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                       info, sizeof(info)) != PSA_SUCCESS) {
        printf("FAIL verify: setup\n");
        failures++;
        return;
    }

    ret |= expect_status("verify mismatch",
                         psa_key_derivation_verify_bytes(&op, wrong,
                                                         sizeof(wrong)),
                         PSA_ERROR_INVALID_SIGNATURE);

    /* The operation is not in an error state: the next call is answered on
     * its merits rather than with BAD_STATE. */
    status = psa_key_derivation_output_bytes(&op, wrong, sizeof(wrong));
    if (status == PSA_ERROR_BAD_STATE) {
        printf("FAIL verify mismatch poisoned the operation\n");
        failures++;
        ret = 1;
    }
    (void)psa_key_derivation_abort(&op);

    if (ret == 0) {
        printf("PASS verify mismatch leaves the operation usable\n");
    }
}

/* A rejected key handle is refused before the operation is touched, so the
 * operation stays usable. Mirrors arch test c019, which calls key_agreement
 * twice on one operation with a bad handle and expects the same status. */
static void test_bad_handle_does_not_poison(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static const uint8_t peer[65] = { 0x04 };
    psa_status_t first;
    psa_status_t second;
    int ret = 0;

    if (psa_key_derivation_setup(&op, PSA_ALG_KEY_AGREEMENT(
                                     PSA_ALG_ECDH,
                                     PSA_ALG_HKDF(PSA_ALG_SHA_256))) !=
        PSA_SUCCESS) {
        printf("SKIP bad handle: ECDH+HKDF setup unsupported\n");
        return;
    }

    first = psa_key_derivation_key_agreement(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, 0xdeadu, peer, sizeof(peer));
    second = psa_key_derivation_key_agreement(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, 0u, peer, sizeof(peer));

    if (first == PSA_SUCCESS || second == PSA_SUCCESS) {
        printf("FAIL bad handle: key agreement unexpectedly succeeded\n");
        failures++;
        ret = 1;
    }
    else if (second == PSA_ERROR_BAD_STATE && first != PSA_ERROR_BAD_STATE) {
        printf("FAIL bad handle poisoned the operation "
               "(first 0x%08x, second 0x%08x)\n",
               (unsigned)first, (unsigned)second);
        failures++;
        ret = 1;
    }
    (void)psa_key_derivation_abort(&op);

    if (ret == 0) {
        printf("PASS a rejected key handle leaves the operation usable\n");
    }
}

/* PSA leaves the operation valid when set_capacity rejects the capacity, so
 * the operation must still derive afterwards. */
static void test_set_capacity_reject_does_not_poison(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t out[16];
    size_t capacity = 0;
    int ret = 0;

    if (setup_expand(&op) != 0) {
        printf("FAIL set_capacity reject: setup\n");
        failures++;
        return;
    }

    if (psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                       info, sizeof(info)) != PSA_SUCCESS) {
        printf("FAIL set_capacity reject: info\n");
        failures++;
        (void)psa_key_derivation_abort(&op);
        return;
    }

    /* Larger than the current capacity: rejected, operation untouched. */
    ret |= expect_status("set_capacity reject",
                         psa_key_derivation_set_capacity(&op, (size_t)-1),
                         PSA_ERROR_INVALID_ARGUMENT);
    ret |= expect_status("capacity readable after reject",
                         psa_key_derivation_get_capacity(&op, &capacity),
                         PSA_SUCCESS);
    ret |= expect_status("output after rejected set_capacity",
                         psa_key_derivation_output_bytes(&op, out, sizeof(out)),
                         PSA_SUCCESS);

    (void)psa_key_derivation_abort(&op);

    if (ret == 0) {
        printf("PASS a rejected capacity leaves the operation usable\n");
    }
}

int main(void)
{
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("PSA KDF error state test: psa_crypto_init failed\n");
        return 1;
    }

    test_rejected_input_poisons();
    test_get_capacity_exempt();
    test_verify_mismatch_does_not_poison();
    test_bad_handle_does_not_poison();
    test_set_capacity_reject_does_not_poison();

    if (failures != 0) {
        printf("PSA KDF error state test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA KDF error state test: OK\n");
    return 0;
}
