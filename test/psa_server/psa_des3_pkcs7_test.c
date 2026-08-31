/* psa_des3_pkcs7_test.c
 *
 * Regression test: wolfpsa_cipher_check_key() restricted
 * PSA_KEY_TYPE_DES keys to CBC_NO_PADDING and ECB_NO_PADDING, so the
 * complete 3DES sub-branches inside the CBC_PKCS7 arms of
 * psa_cipher_update()/psa_cipher_finish() were dead code even though
 * the block/padding logic is generic over block_size. CBC_PKCS7 is now
 * admitted for DES keys; this test roundtrips it.
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

static int make_des3_key(psa_key_id_t* key_id)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    uint8_t key[24];
    psa_status_t st;
    int i;

    for (i = 0; i < (int)sizeof(key); i++) {
        key[i] = (uint8_t)(i * 5 + 3);
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_DES);
    psa_set_key_bits(&attrs, 192);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, key, sizeof(key), key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL import des3 key status=%d\n", (int)st);
        return 1;
    }
    return 0;
}

static int test_oneshot_roundtrip(psa_key_id_t key_id, const uint8_t* msg,
                                  size_t msg_len, const char* label)
{
    uint8_t ct[128];
    uint8_t pt[128];
    size_t ct_len = 0;
    size_t pt_len = 0;
    psa_status_t st;
    int ok = 0;

    st = psa_cipher_encrypt(key_id, PSA_ALG_CBC_PKCS7, msg, msg_len, ct,
                            sizeof(ct), &ct_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s encrypt status=%d\n", label, (int)st);
        return 1;
    }
    if (ct_len != (msg_len / 8 + 1) * 8 + 8) {
        printf("FAIL %s ct_len=%u expected=%u\n", label, (unsigned)ct_len,
               (unsigned)((msg_len / 8 + 1) * 8 + 8));
        return 1;
    }

    st = psa_cipher_decrypt(key_id, PSA_ALG_CBC_PKCS7, ct, ct_len, pt,
                            sizeof(pt), &pt_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s decrypt status=%d\n", label, (int)st);
        goto out;
    }
    if (pt_len != msg_len || memcmp(pt, msg, msg_len) != 0) {
        printf("FAIL %s roundtrip mismatch (len=%u)\n", label,
               (unsigned)pt_len);
        goto out;
    }

    ok = 1;

out:
    return ok ? 0 : 1;
}

static int test_multipart_roundtrip(psa_key_id_t key_id)
{
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_cipher_operation_t op_d = psa_cipher_operation_init();
    static const uint8_t msg[11] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'
    };
    uint8_t iv[8];
    uint8_t ct[64];
    uint8_t pt[64];
    size_t iv_len = 0;
    size_t ct_len = 0;
    size_t part_len = 0;
    size_t fin_len = 0;
    size_t pt_len = 0;
    size_t dfin_len = 0;
    psa_status_t st;
    int ok = 0;

    /* 8 + 3 bytes through the update full/partial-block paths; the
     * first update must emit the first block so the output offset
     * actually accumulates across updates. */
    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp setup status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_generate_iv(&op, iv, sizeof(iv), &iv_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp generate_iv status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op, msg, 8, ct, sizeof(ct), &part_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp update1 status=%d\n", (int)st);
        return 1;
    }
    ct_len += part_len;
    st = psa_cipher_update(&op, msg + 8, 3, ct + ct_len,
                           sizeof(ct) - ct_len, &part_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp update2 status=%d\n", (int)st);
        return 1;
    }
    ct_len += part_len;
    st = psa_cipher_finish(&op, ct + ct_len, sizeof(ct) - ct_len, &fin_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp finish status=%d\n", (int)st);
        return 1;
    }
    ct_len += fin_len;

    st = psa_cipher_decrypt_setup(&op_d, key_id, PSA_ALG_CBC_PKCS7);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp dsetup status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_set_iv(&op_d, iv, iv_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp set_iv status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_update(&op_d, ct, ct_len, pt, sizeof(pt), &pt_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp dupdate status=%d\n", (int)st);
        return 1;
    }
    st = psa_cipher_finish(&op_d, pt + pt_len, sizeof(pt) - pt_len,
                           &dfin_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL mp dfinish status=%d (padding)\n", (int)st);
        return 1;
    }
    pt_len += dfin_len;

    if (pt_len != sizeof(msg) || memcmp(pt, msg, sizeof(msg)) != 0) {
        printf("FAIL mp roundtrip mismatch (len=%u)\n", (unsigned)pt_len);
        goto out;
    }

    ok = 1;

out:
    (void)psa_cipher_abort(&op);
    (void)psa_cipher_abort(&op_d);
    return ok ? 0 : 1;
}

int main(void)
{
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    static const uint8_t msg_a[10] = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
    static const uint8_t msg_b[16] = {
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'
    };
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    if (make_des3_key(&key_id) != 0) {
        return 1;
    }

    rc |= test_oneshot_roundtrip(key_id, msg_a, sizeof(msg_a),
                                 "oneshot-10B");
    rc |= test_oneshot_roundtrip(key_id, msg_b, sizeof(msg_b),
                                 "oneshot-16B");
    rc |= test_multipart_roundtrip(key_id);

    (void)psa_destroy_key(key_id);

    if (rc != 0) {
        printf("PSA des3 pkcs7 test: FAIL\n");
        return 1;
    }

    printf("PSA des3 pkcs7 test: OK\n");
    return 0;
}
