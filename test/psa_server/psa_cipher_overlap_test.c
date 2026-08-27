/* psa_cipher_overlap_test.c
 *
 * Regression test: psa_cipher_encrypt() wrote the generated
 * IV into the output buffer before reading the input, so with input and
 * output ranges overlapping (e.g. the same buffer for both) the IV
 * clobbered unread plaintext and the operation silently encrypted the
 * wrong data.
 *
 * The chosen contract: overlapping input and output buffers are rejected
 * with PSA_ERROR_NOT_SUPPORTED (the in-tree PSA header makes no
 * overlap guarantee for the one-shot cipher API, and the block-cipher
 * paths read input while writing output).
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

static int make_aes_key(psa_key_id_t* key_id, psa_algorithm_t alg)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate_key(%s) status=%d\n",
               (alg == PSA_ALG_CBC_NO_PADDING) ? "nopad" : "pkcs7",
               (int)st);
        return 1;
    }
    return 0;
}

int main(void)
{
    psa_key_id_t nopad_id = PSA_KEY_ID_NULL;
    psa_key_id_t pkcs7_id = PSA_KEY_ID_NULL;
    uint8_t buf[64];
    uint8_t plain[16];
    uint8_t ct[64];
    size_t ct_len = 0;
    int i;
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    if (make_aes_key(&nopad_id, PSA_ALG_CBC_NO_PADDING) != 0) {
        return 1;
    }
    if (make_aes_key(&pkcs7_id, PSA_ALG_CBC_PKCS7) != 0) {
        return 1;
    }

    for (i = 0; i < (int)sizeof(plain); i++) {
        plain[i] = (uint8_t)(i + 1);
    }
    memcpy(buf, plain, sizeof(plain));

    /* Exact in-place: same 32-byte range used as input and output.
     * Pre-fix this returned SUCCESS after clobbering the plaintext. */
    ct_len = 0;
    if (psa_cipher_encrypt(nopad_id, PSA_ALG_CBC_NO_PADDING, buf, 16,
                           buf, 32, &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place nopad: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    ct_len = 0;
    if (psa_cipher_encrypt(pkcs7_id, PSA_ALG_CBC_PKCS7, buf, 16,
                           buf, 32, &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place pkcs7: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* Partial overlap: output starts inside the input range. */
    ct_len = 0;
    if (psa_cipher_encrypt(nopad_id, PSA_ALG_CBC_NO_PADDING, buf, 16,
                           buf + 8, 48, &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL partial-overlap: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* Disjoint control: a normal one-shot encryption still works. */
    ct_len = 0;
    if (psa_cipher_encrypt(nopad_id, PSA_ALG_CBC_NO_PADDING, plain, 16,
                           ct, sizeof(ct), &ct_len) != PSA_SUCCESS) {
        printf("FAIL disjoint encrypt status\n");
        rc = 1;
    }
    else if (ct_len != 32) {
        printf("FAIL disjoint encrypt len=%u expected=32\n",
               (unsigned)ct_len);
        rc = 1;
    }

    /* Adjacent buffers (no overlap) must still be accepted: output
     * starts exactly where the input ends. */
    ct_len = 0;
    if (psa_cipher_encrypt(nopad_id, PSA_ALG_CBC_NO_PADDING, buf, 16,
                           buf + 16, 48, &ct_len) != PSA_SUCCESS) {
        printf("FAIL adjacent encrypt: expected SUCCESS\n");
        rc = 1;
    }

    (void)psa_destroy_key(nopad_id);
    (void)psa_destroy_key(pkcs7_id);

    if (rc != 0) {
        printf("PSA cipher overlap test: FAIL\n");
        return 1;
    }

    printf("PSA cipher overlap test: OK\n");
    return 0;
}
