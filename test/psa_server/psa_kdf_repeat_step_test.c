/* psa_kdf_repeat_step_test.c
 *
 * Regression: the KDF step validators did not reject a step already
 * recorded in steps_set (except SP800-108). psa_key_derivation_input_bytes
 * appends each value to the step buffer, so a repeated SALT, INFO,
 * LABEL, SEED, or PBKDF2 input was silently concatenated instead of
 * returning PSA_ERROR_BAD_STATE, although the PSA KDF definitions allow
 * each input to be passed only once.
 *
 * The validator now rejects a repeated step for every KDF in one place,
 * before the per-algorithm dispatch, preserving the ordering checks.
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

typedef struct repeat_case {
    psa_algorithm_t alg;
    psa_key_derivation_step_t prefix[3];
    psa_key_derivation_step_t repeat;
} repeat_case_t;

/* Each case: set the prefix steps (0 terminates), then the repeat step
 * must be rejected with PSA_ERROR_BAD_STATE. 32-byte inputs are valid
 * for every step used, including HKDF-Expand SECRET (one SHA-256 hash
 * length). */
static const repeat_case_t cases[] = {
    {PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_SALT, 0, 0},
     PSA_KEY_DERIVATION_INPUT_SALT},
    {PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_SALT, PSA_KEY_DERIVATION_INPUT_SECRET, 0},
     PSA_KEY_DERIVATION_INPUT_SECRET},
    {PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_SECRET, PSA_KEY_DERIVATION_INPUT_INFO, 0},
     PSA_KEY_DERIVATION_INPUT_INFO},
    {PSA_ALG_HKDF(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_SALT, 0, 0},
     PSA_KEY_DERIVATION_INPUT_SALT},
    {PSA_ALG_HKDF(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_INFO, 0, 0},
     PSA_KEY_DERIVATION_INPUT_INFO},
    {PSA_ALG_TLS12_PRF(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_LABEL, 0, 0},
     PSA_KEY_DERIVATION_INPUT_LABEL},
    {PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_SEED, 0, 0},
     PSA_KEY_DERIVATION_INPUT_SEED},
    {PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_PASSWORD, 0, 0},
     PSA_KEY_DERIVATION_INPUT_PASSWORD},
    {PSA_ALG_SP800_108_COUNTER_HMAC(PSA_ALG_SHA_256),
     {PSA_KEY_DERIVATION_INPUT_LABEL, 0, 0},
     PSA_KEY_DERIVATION_INPUT_LABEL},
};

static int failures;

static int run_case(const repeat_case_t *c, size_t index)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    uint8_t data[32];
    psa_status_t status;
    int ret = 0;
    int i;

    memset(data, 0x5a, sizeof(data));

    status = psa_key_derivation_setup(&op, c->alg);
    if (status != PSA_SUCCESS) {
        printf("FAIL case %zu: setup status 0x%08x\n", index,
               (unsigned)status);
        return 1;
    }

    for (i = 0; c->prefix[i] != 0; i++) {
        status = psa_key_derivation_input_bytes(&op, c->prefix[i], data,
                                                sizeof(data));
        if (status != PSA_SUCCESS) {
            printf("FAIL case %zu: prefix step %d status 0x%08x\n",
                   index, c->prefix[i], (unsigned)status);
            ret = 1;
            break;
        }
    }

    if (ret == 0) {
        status = psa_key_derivation_input_bytes(&op, c->repeat, data,
                                                sizeof(data));
        if (status != PSA_ERROR_BAD_STATE) {
            printf("FAIL case %zu: repeated step %d status 0x%08x "
                   "want 0x%08x\n", index, c->repeat, (unsigned)status,
                   (unsigned)PSA_ERROR_BAD_STATE);
            ret = 1;
        }
    }

    (void)psa_key_derivation_abort(&op);

    return ret;
}

/* The PBKDF2 salt is the documented exception to the single-use rule: the
 * PSA API specifies it as "one or more times", with the parts concatenated.
 * Repeating it must be accepted, and must derive the same key as a single
 * input holding the concatenation. */
static int test_pbkdf2_cost_is_single_use(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t status;

    if (psa_key_derivation_setup(&op,
                                 PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) !=
        PSA_SUCCESS ||
        psa_key_derivation_input_integer(&op, PSA_KEY_DERIVATION_INPUT_COST,
                                         16) != PSA_SUCCESS) {
        printf("FAIL single-use cost: setup\n");
        (void)psa_key_derivation_abort(&op);
        return 1;
    }

    status = psa_key_derivation_input_integer(&op,
                                              PSA_KEY_DERIVATION_INPUT_COST,
                                              16);
    (void)psa_key_derivation_abort(&op);
    if (status != PSA_ERROR_BAD_STATE) {
        printf("FAIL single-use cost: status 0x%08x want 0x%08x\n",
               (unsigned)status, (unsigned)PSA_ERROR_BAD_STATE);
        return 1;
    }
    return 0;
}

static int test_pbkdf2_salt_is_multipart(void)
{
    static const uint8_t salt[8] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    static const uint8_t password[16] = {
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64,
        0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64
    };
    psa_key_derivation_operation_t split = psa_key_derivation_operation_init();
    psa_key_derivation_operation_t whole = psa_key_derivation_operation_init();
    uint8_t split_out[32];
    uint8_t whole_out[32];
    psa_status_t status;
    int ret = 0;

    ret |= (psa_key_derivation_setup(&split,
                                     PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) !=
            PSA_SUCCESS);
    ret |= (psa_key_derivation_input_integer(&split,
                                             PSA_KEY_DERIVATION_INPUT_COST,
                                             16) != PSA_SUCCESS);
    if (ret != 0) {
        printf("FAIL multipart salt: setup\n");
        (void)psa_key_derivation_abort(&split);
        return 1;
    }

    status = psa_key_derivation_input_bytes(&split,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt, 4);
    if (status != PSA_SUCCESS) {
        printf("FAIL multipart salt: first salt status 0x%08x\n",
               (unsigned)status);
        (void)psa_key_derivation_abort(&split);
        return 1;
    }
    status = psa_key_derivation_input_bytes(&split,
                                            PSA_KEY_DERIVATION_INPUT_SALT,
                                            salt + 4, 4);
    if (status != PSA_SUCCESS) {
        printf("FAIL multipart salt: second salt status 0x%08x want 0x%08x\n",
               (unsigned)status, (unsigned)PSA_SUCCESS);
        (void)psa_key_derivation_abort(&split);
        return 1;
    }

    ret |= (psa_key_derivation_input_bytes(&split,
                                           PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                           password, sizeof(password)) !=
            PSA_SUCCESS);
    ret |= (psa_key_derivation_output_bytes(&split, split_out,
                                            sizeof(split_out)) != PSA_SUCCESS);
    (void)psa_key_derivation_abort(&split);
    if (ret != 0) {
        printf("FAIL multipart salt: split derivation\n");
        return 1;
    }

    ret |= (psa_key_derivation_setup(&whole,
                                     PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)) !=
            PSA_SUCCESS);
    ret |= (psa_key_derivation_input_integer(&whole,
                                             PSA_KEY_DERIVATION_INPUT_COST,
                                             16) != PSA_SUCCESS);
    ret |= (psa_key_derivation_input_bytes(&whole,
                                           PSA_KEY_DERIVATION_INPUT_SALT,
                                           salt, sizeof(salt)) != PSA_SUCCESS);
    ret |= (psa_key_derivation_input_bytes(&whole,
                                           PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                           password, sizeof(password)) !=
            PSA_SUCCESS);
    ret |= (psa_key_derivation_output_bytes(&whole, whole_out,
                                            sizeof(whole_out)) != PSA_SUCCESS);
    (void)psa_key_derivation_abort(&whole);
    if (ret != 0) {
        printf("FAIL multipart salt: single-input derivation\n");
        return 1;
    }

    if (memcmp(split_out, whole_out, sizeof(split_out)) != 0) {
        printf("FAIL multipart salt: split salt did not concatenate\n");
        return 1;
    }

    return 0;
}

int main(void)
{
    size_t i;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("PSA KDF repeat step test: psa_crypto_init failed\n");
        return 1;
    }

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        failures += run_case(&cases[i], i);
    }

    failures += test_pbkdf2_cost_is_single_use();
    failures += test_pbkdf2_salt_is_multipart();

    if (failures != 0) {
        printf("PSA KDF repeat step test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA KDF repeat step test: OK\n");
    return 0;
}
