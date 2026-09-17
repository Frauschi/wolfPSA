/* psa_kdf_zeroize_output_test.c
 *
 * Regression: on the direct-output path of psa_key_derivation_output_bytes()
 * the iterative KDF backends (PBKDF2-AES-CMAC, SP800-108 HMAC/CMAC) stream
 * each completed block straight into the caller-owned output buffer. When a
 * later block's crypto call failed mid-stream, the cleanup only zeroized the
 * local stack intermediates and the partial derived output was left in the
 * caller buffer. The direct path now zeroizes the output whenever
 * wolfpsa_kdf_compute_output() returns non-success.
 *
 * A mid-stream backend failure is not reachable through the public API with
 * the software backend, so the test drives one through a wolfCrypt crypto
 * callback: a device that "computes" the first HMAC block (writing non-zero
 * material) and fails on the second. That is exactly the trigger the finding
 * names (a crypto callback on a later iteration). The test therefore links
 * the WOLF_CRYPTO_CB build of the library, like psa_devid_cryptocb_test.
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

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/types.h>

#include <wolfpsa/psa/crypto.h>
#include <wolfpsa/psa_engine.h>

#include <stdio.h>
#include <string.h>

/* Arbitrary devId standing in for a failing offload backend. */
#define TEST_DEVID 0x505343

/* Two 32-byte SHA-256 blocks: the first completes, the second fails. */
#define OUT_LEN 64

static int hmac_final_count;

/* First HMAC final "succeeds" and writes non-zero material (so the caller
 * buffer holds partial derived output); every later final fails, standing in
 * for a backend error on a later derivation block. SETKEY and UPDATE fall
 * back to software so the derivation reaches the final of each block. */
static int fail_cb(int devId, wc_CryptoInfo *info, void *ctx)
{
    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return CRYPTOCB_UNAVAILABLE;
    }
    if (info->algo_type == WC_ALGO_TYPE_HMAC &&
        info->hmac.in == NULL && info->hmac.digest != NULL) {
        int i;
        int digest_len;

        hmac_final_count++;
        if (hmac_final_count == 1) {
            digest_len = wc_HmacSizeByType(info->hmac.macType);
            if (digest_len <= 0) {
                return CRYPTOCB_UNAVAILABLE;
            }
            for (i = 0; i < digest_len; i++) {
                info->hmac.digest[i] = (byte)0xa5;
            }
            return 0;
        }
        return -12345;
    }

    return CRYPTOCB_UNAVAILABLE;
}

static int buffer_is_zero(const uint8_t *buf, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (buf[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/* Software control: the same multi-block derivation succeeds and produces
 * non-zero output, proving the direct path writes into the caller buffer. */
static int test_control_success(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static uint8_t key_in[16];
    uint8_t out[OUT_LEN];
    psa_status_t status;
    int ret = 0;

    memset(key_in, 0x11, sizeof(key_in));

    if (wolfPSA_SetDefaultDevID(INVALID_DEVID) != 0) {
        printf("FAIL control: set devId\n");
        return 1;
    }
    ret |= (psa_key_derivation_setup(&op,
                                     PSA_ALG_SP800_108_COUNTER_HMAC(
                                         PSA_ALG_SHA_256)) != PSA_SUCCESS);
    ret |= (psa_key_derivation_input_bytes(&op,
                                           PSA_KEY_DERIVATION_INPUT_SECRET,
                                           key_in, sizeof(key_in)) !=
            PSA_SUCCESS);
    status = psa_key_derivation_output_bytes(&op, out, sizeof(out));
    (void)psa_key_derivation_abort(&op);
    if (ret != 0) {
        printf("FAIL control: setup/input (ret=%d)\n", ret);
        return 1;
    }
    if (status != PSA_SUCCESS) {
        printf("FAIL control: output status=%d\n", (int)status);
        return 1;
    }
    if (buffer_is_zero(out, sizeof(out))) {
        printf("FAIL control: software output unexpectedly all zero\n");
        return 1;
    }
    return 0;
}

/* The regression: a mid-stream backend failure must leave the caller buffer
 * fully zeroized, with the error still propagated. */
static int test_midstream_failure_zeroizes(void)
{
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    static uint8_t key_in[16];
    uint8_t out[OUT_LEN];
    psa_status_t status;
    int ret = 0;

    memset(key_in, 0x22, sizeof(key_in));
    memset(out, 0xff, sizeof(out));
    hmac_final_count = 0;

    if (wc_CryptoCb_RegisterDevice(TEST_DEVID, fail_cb, NULL) != 0) {
        printf("FAIL midstream: register device\n");
        return 1;
    }
    if (wolfPSA_SetDefaultDevID(TEST_DEVID) != 0) {
        printf("FAIL midstream: set devId\n");
        return 1;
    }

    ret |= (psa_key_derivation_setup(&op,
                                     PSA_ALG_SP800_108_COUNTER_HMAC(
                                         PSA_ALG_SHA_256)) != PSA_SUCCESS);
    ret |= (psa_key_derivation_input_bytes(&op,
                                           PSA_KEY_DERIVATION_INPUT_SECRET,
                                           key_in, sizeof(key_in)) !=
            PSA_SUCCESS);
    status = psa_key_derivation_output_bytes(&op, out, sizeof(out));
    (void)psa_key_derivation_abort(&op);

    (void)wolfPSA_SetDefaultDevID(WOLFPSA_DEVID_DEFAULT);

    if (ret != 0) {
        printf("FAIL midstream: setup/input (ret=%d)\n", ret);
        return 1;
    }
    if (hmac_final_count < 2) {
        printf("FAIL midstream: expected >=2 hmac finals, got %d\n",
               hmac_final_count);
        return 1;
    }
    if (status == PSA_SUCCESS) {
        printf("FAIL midstream: expected an error, got success\n");
        return 1;
    }
    if (!buffer_is_zero(out, sizeof(out))) {
        printf("FAIL midstream: partial derived output left in caller buffer\n")
        ;
        return 1;
    }
    return 0;
}

int main(void)
{
    psa_status_t init;
    int failures = 0;

    init = psa_crypto_init();
    if (init != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)init);
        return 1;
    }

    failures += test_control_success();
    failures += test_midstream_failure_zeroizes();

    if (failures != 0) {
        printf("PSA KDF zeroize output test: FAIL (%d)\n", failures);
        return 1;
    }

    printf("PSA KDF zeroize output test: OK\n");
    return 0;
}
