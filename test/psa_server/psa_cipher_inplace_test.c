/* psa_cipher_inplace_test.c
 *
 * Regression test: the buffered block handling in
 * psa_cipher_update assembles a completed block from the partial buffer
 * plus the first bytes of the input, writes the ciphertext to the start
 * of the output, and only then reads the rest of the input. With input
 * and output ranges overlapping (e.g. the exact same buffer for both,
 * the in-place pattern) the first write clobbered not-yet-read input
 * bytes and the operation silently produced wrong ciphertext.
 *
 * The chosen contract (same as the one-shot overlap test): overlapping input and output
 * ranges are rejected with PSA_ERROR_NOT_SUPPORTED.
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
#include <string.h>

#include <psa/crypto.h>

int main(void)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_cipher_operation_t op2 = psa_cipher_operation_init();
    uint8_t iv[16];
    uint8_t iv_ref[16];
    uint8_t buf[32];
    uint8_t plain[16];
    uint8_t ct[32];
    uint8_t ct2[32];
    size_t iv_len = 0;
    size_t out_len = 0;
    size_t out_len2 = 0;
    size_t fin_len = 0;
    psa_status_t st;
    int i;
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);
    if (psa_generate_key(&attrs, &key_id) != PSA_SUCCESS) {
        printf("FAIL generate_key\n");
        return 1;
    }

    for (i = 0; i < (int)sizeof(plain); i++) {
        plain[i] = (uint8_t)(i * 3 + 1);
    }
    memcpy(buf, plain, sizeof(plain));

    /* Reference: a non-overlapping multipart update of all 16 bytes. */
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_generate_iv(&op, iv, sizeof(iv), &iv_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate_iv status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op, plain, 16, ct, sizeof(ct), &out_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL reference update status=%d\n", (int)st);
        return 1;
    }
    if (out_len != 16) {
        printf("FAIL reference update len=%u\n", (unsigned)out_len);
        return 1;
    }
    st = psa_cipher_finish(&op, ct + out_len, sizeof(ct) - out_len,
                           &fin_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL reference finish status=%d\n", (int)st);
        return 1;
    }
    memcpy(iv_ref, iv, sizeof(iv_ref));
    (void)psa_cipher_abort(&op);

    /* Case 1: exact in-place, one full block as both input and output.
     * Pre-fix this returned SUCCESS after writing over the plaintext. */
    st = psa_cipher_encrypt_setup(&op2, key_id, PSA_ALG_CBC_NO_PADDING);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup2 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_set_iv(&op2, iv_ref, sizeof(iv_ref));
    if (st != PSA_SUCCESS) {
        printf("FAIL set_iv2 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op2, buf, 16, buf, 32, &out_len);
    if (st != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place update: expected NOT_SUPPORTED got %d\n",
               (int)st);
        rc = 1;
    }
    (void)psa_cipher_abort(&op2);

    /* Case 2: the finding's trigger shape - a 5-byte partial buffer, then
     * a 27-byte continuation in the same 32-byte buffer used as input
     * and output. Both overlapping calls must be rejected (each on its
     * own operation, since a failed update aborts the operation). */
    st = psa_cipher_encrypt_setup(&op2, key_id, PSA_ALG_CBC_NO_PADDING);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup3 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_set_iv(&op2, iv_ref, sizeof(iv_ref));
    if (st != PSA_SUCCESS) {
        printf("FAIL set_iv3 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op2, buf, 5, buf, 32, &out_len);
    if (st != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place partial update: expected NOT_SUPPORTED "
               "got %d\n", (int)st);
        rc = 1;
    }
    (void)psa_cipher_abort(&op2);

    st = psa_cipher_encrypt_setup(&op2, key_id, PSA_ALG_CBC_NO_PADDING);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup3b status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_set_iv(&op2, iv_ref, sizeof(iv_ref));
    if (st != PSA_SUCCESS) {
        printf("FAIL set_iv3b status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op2, buf, 27, buf, 32, &out_len);
    if (st != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place continuation update: expected "
               "NOT_SUPPORTED got %d\n", (int)st);
        rc = 1;
    }
    (void)psa_cipher_abort(&op2);

    /* Case 3: non-overlapping multipart (5 + 11 bytes) with the same IV
     * as the reference still works and matches the reference
     * ciphertext. */
    st = psa_cipher_encrypt_setup(&op2, key_id, PSA_ALG_CBC_NO_PADDING);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup4 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_set_iv(&op2, iv_ref, sizeof(iv_ref));
    if (st != PSA_SUCCESS) {
        printf("FAIL set_iv4 status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op2, plain, 5, ct2, sizeof(ct2), &out_len2);
    if (st != PSA_SUCCESS) {
        printf("FAIL multipart update1 status=%d\n", (int)st);
        rc = 1;
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_update(&op2, plain + 5, 11, ct2 + out_len2,
                               sizeof(ct2) - out_len2, &out_len2);
        if (st != PSA_SUCCESS) {
            printf("FAIL multipart update2 status=%d\n", (int)st);
            rc = 1;
        }
        if (st == PSA_SUCCESS) {
            st = psa_cipher_finish(&op2, ct2 + out_len2,
                                   sizeof(ct2) - out_len2, &fin_len);
            if (st != PSA_SUCCESS) {
                printf("FAIL multipart finish status=%d\n", (int)st);
                rc = 1;
            }
            if (st == PSA_SUCCESS &&
                (out_len2 != 16 || memcmp(ct, ct2, 16) != 0)) {
                printf("FAIL multipart ciphertext mismatch "
                       "(len=%u)\n", (unsigned)out_len2);
                rc = 1;
            }
        }
    }
    (void)psa_cipher_abort(&op2);

    (void)psa_destroy_key(key_id);

    if (rc != 0) {
        printf("PSA cipher inplace test: FAIL\n");
        return 1;
    }

    printf("PSA cipher inplace test: OK\n");
    return 0;
}
