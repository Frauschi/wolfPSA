/* Regression: the XOF public API must exist in every build.
 *
 * crypto.h declares psa_xof_* unconditionally and wolfpsa.map exports
 * them, but the definitions were wrapped in the SHAKE feature guard, so
 * a build without SHAKE128/SHAKE256 failed at link time for any
 * consumer calling an XOF API.
 *
 * This test links the full XOF API in both configurations and detects
 * the backend at run time:
 *  - with a SHAKE backend: a normal setup/update/output/abort flow;
 *  - without: setup must report PSA_ERROR_NOT_SUPPORTED and the
 *    remaining calls must report the inactive-operation errors.
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

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

int main(void)
{
    psa_status_t status;
    psa_xof_operation_t op;
    uint8_t input[8];
    uint8_t output[32];

    op = psa_xof_operation_init();
    memset(input, 0x3c, sizeof(input));

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    status = psa_xof_setup(&op, PSA_ALG_SHAKE128);
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        /* Build without a SHAKE backend: the API must exist and report
         * the not-supported / inactive-operation errors. */
        expect(status, PSA_ERROR_NOT_SUPPORTED, "setup without backend");
        expect(psa_xof_set_context(&op, input, sizeof(input)),
               PSA_ERROR_BAD_STATE, "set_context without backend");
        expect(psa_xof_update(&op, input, sizeof(input)), PSA_ERROR_BAD_STATE,
               "update without backend");
        expect(psa_xof_output(&op, output, sizeof(output)),
               PSA_ERROR_BAD_STATE, "output without backend");
        expect(psa_xof_abort(&op), PSA_SUCCESS, "abort without backend");
    }
    else {
        expect(status, PSA_SUCCESS, "setup");
        expect(psa_xof_update(&op, input, sizeof(input)), PSA_SUCCESS,
               "update");
        expect(psa_xof_output(&op, output, sizeof(output)), PSA_SUCCESS,
               "output");
        expect(psa_xof_abort(&op), PSA_SUCCESS, "abort");
        expect(psa_xof_update(&op, input, sizeof(input)), PSA_ERROR_BAD_STATE,
               "update after abort");
    }

    if (failures == 0) {
        printf("xof-symbols tests: all passed\n");
        return 0;
    }
    printf("xof-symbols tests: %d failure(s)\n", failures);
    return 1;
}
