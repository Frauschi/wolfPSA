/* psa_cipher_overlap_test.c
 *
 * Regression test: psa_cipher_encrypt() wrote the generated
 * IV into the output buffer before reading the input, so with input and
 * output ranges overlapping (e.g. the same buffer for both) the IV
 * clobbered unread plaintext and the operation silently encrypted the
 * wrong data.
 *
 * The chosen contract for the one-shot entry points: any overlap
 * between the declared input and output ranges is rejected with
 * PSA_ERROR_NOT_SUPPORTED, in every mode. The in-tree PSA header makes
 * no overlap guarantee for the one-shot cipher API; the generated IV
 * is written to the output before the input is consumed, and the
 * block-cipher paths read input while writing output. A byte-wise safe
 * in-place stream call (for example CTR with the IV region disjoint
 * from the update region) is rejected as well; the multipart API is
 * the in-place path, and this file pins that one-shot overlap is
 * rejected there too.
 *
 * The multipart update() applies the same contract only to the block
 * modes (their partial-block buffering makes overlap unsafe); the
 * stream modes (CTR, CFB, OFB, CCM*, ChaCha20) buffer nothing and are
 * in-place safe, so an in-place update must succeed and must produce
 * the same bytes as a disjoint update.
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

static int make_key(psa_key_id_t *key_id, psa_key_type_t key_type,
                    size_t key_bits, psa_algorithm_t alg, const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, key_type);
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate_key(%s) status=%d\n", name, (int)st);
        return 1;
    }
    return 0;
}

/* Three-key DES is imported as PSA_KEY_TYPE_DES with 192 bits.
 * (psa_generate_key does not cover it.) */
static int make_des3_key(psa_key_id_t *key_id, psa_algorithm_t alg)
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
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_import_key(&attrs, key, sizeof(key), key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL import_key(des3-pkcs7) status=%d\n", (int)st);
        return 1;
    }
    return 0;
}

/* Multipart update with input and output on the same range. The
 * block modes must reject it with PSA_ERROR_NOT_SUPPORTED. */
static int block_update_rejects_overlap(psa_algorithm_t alg, const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_cipher_operation_t op;
    uint8_t iv[16];
    uint8_t buf[48];
    size_t len = 0;
    psa_status_t st;
    int i;
    int rc = 0;

    for (i = 0; i < (int)sizeof(iv); i++) {
        iv[i] = (uint8_t)i;
    }
    for (i = 0; i < (int)sizeof(buf); i++) {
        buf[i] = (uint8_t)(i + 1);
    }

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, &key);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate_key(%s) status=%d\n", name, (int)st);
        return 1;
    }

    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key, alg);
    if (st != PSA_SUCCESS) {
        printf("FAIL setup(%s) status=%d\n", name, (int)st);
        return 1;
    }
    if (alg != PSA_ALG_ECB_NO_PADDING) {
        st = psa_cipher_set_iv(&op, iv, sizeof(iv));
        if (st != PSA_SUCCESS) {
            printf("FAIL set_iv(%s) status=%d\n", name, (int)st);
            return 1;
        }
    }

    st = psa_cipher_update(&op, buf, 16, buf, sizeof(buf), &len);
    if (st != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL update in-place %s: expected NOT_SUPPORTED got %d\n",
               name, (int)st);
        rc = 1;
    }

    psa_cipher_abort(&op);
    (void)psa_destroy_key(key);
    return rc;
}

/* Multipart update with input and output on the same range. The
 * stream modes must accept it and produce the same bytes as the
 * same update with disjoint buffers. */
static int stream_inplace_matches_reference(psa_key_type_t key_type,
                                            size_t key_bits,
                                            psa_algorithm_t alg,
                                            size_t iv_len,
                                            const char *name)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_cipher_operation_t op;
    uint8_t iv[16];
    uint8_t inplace[48];
    uint8_t reference_in[48];
    uint8_t reference_out[48];
    size_t ref_up_len = 0;
    size_t ref_fin_len = 0;
    size_t ip_up_len = 0;
    size_t ip_fin_len = 0;
    psa_status_t st;
    int i;
    int rc = 0;

    for (i = 0; i < (int)sizeof(iv); i++) {
        iv[i] = (uint8_t)(0x30 + i);
    }
    for (i = 0; i < (int)sizeof(reference_in); i++) {
        reference_in[i] = (uint8_t)(0x60 + i);
    }
    memcpy(inplace, reference_in, sizeof(inplace));

    psa_set_key_type(&attrs, key_type);
    psa_set_key_bits(&attrs, key_bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, alg);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_VOLATILE);

    st = psa_generate_key(&attrs, &key);
    if (st != PSA_SUCCESS) {
        printf("FAIL generate_key(%s) status=%d\n", name, (int)st);
        return 1;
    }

    /* Reference run: disjoint input and output buffers. */
    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key, alg);
    if (st == PSA_SUCCESS) {
        st = psa_cipher_set_iv(&op, iv, iv_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_update(&op, reference_in, sizeof(reference_in),
                               reference_out, sizeof(reference_out),
                               &ref_up_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_finish(&op, reference_out + ref_up_len,
                               sizeof(reference_out) - ref_up_len,
                               &ref_fin_len);
    }
    if (st != PSA_SUCCESS) {
        printf("FAIL reference %s: status=%d\n", name, (int)st);
        rc = 1;
    }
    psa_cipher_abort(&op);

    /* In-place run: same key, same IV, same plaintext. */
    op = psa_cipher_operation_init();
    st = psa_cipher_encrypt_setup(&op, key, alg);
    if (st == PSA_SUCCESS) {
        st = psa_cipher_set_iv(&op, iv, iv_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_update(&op, inplace, sizeof(inplace),
                               inplace, sizeof(inplace), &ip_up_len);
    }
    if (st == PSA_SUCCESS) {
        st = psa_cipher_finish(&op, inplace + ip_up_len,
                               sizeof(inplace) - ip_up_len, &ip_fin_len);
    }
    if (st != PSA_SUCCESS) {
        printf("FAIL in-place %s: expected SUCCESS got %d\n", name,
               (int)st);
        rc = 1;
    }
    else if (rc == 0 &&
             (ip_up_len + ip_fin_len != ref_up_len + ref_fin_len ||
              memcmp(inplace, reference_out, ref_up_len + ref_fin_len) != 0)) {
        printf("FAIL in-place %s: bytes differ from reference\n", name);
        rc = 1;
    }
    psa_cipher_abort(&op);

    (void)psa_destroy_key(key);
    return rc;
}

int main(void)
{
    psa_key_id_t nopad_id = PSA_KEY_ID_NULL;
    psa_key_id_t pkcs7_id = PSA_KEY_ID_NULL;
    psa_key_id_t ctr_id = PSA_KEY_ID_NULL;
    psa_key_id_t des3_id = PSA_KEY_ID_NULL;
    uint8_t buf[64];
    uint8_t fbuf[96];
    uint8_t sbuf[48];
    uint8_t plain[16];
    uint8_t ct[64];
    size_t ct_len = 0;
    int i;
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    if (make_key(&nopad_id, PSA_KEY_TYPE_AES, 128, PSA_ALG_CBC_NO_PADDING,
                 "nopad") != 0) {
        return 1;
    }
    if (make_key(&pkcs7_id, PSA_KEY_TYPE_AES, 128, PSA_ALG_CBC_PKCS7,
                 "pkcs7") != 0) {
        return 1;
    }
    if (make_key(&ctr_id, PSA_KEY_TYPE_AES, 128, PSA_ALG_CTR, "ctr") != 0) {
        return 1;
    }
    if (make_des3_key(&des3_id, PSA_ALG_CBC_PKCS7) != 0) {
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

    /* The one-shot contract is all-modes: even a byte-wise safe
     * in-place stream call is rejected when the declared ranges
     * overlap. The IV region sbuf[0..15] is disjoint from the input
     * sbuf[16..47], and a CTR update there would be safe, but the
     * declared output range sbuf[0..47] overlaps the input range, so
     * the one-shot entry point refuses it. */
    for (i = 0; i < (int)sizeof(sbuf); i++) {
        sbuf[i] = (uint8_t)(i + 1);
    }
    ct_len = 0;
    if (psa_cipher_encrypt(ctr_id, PSA_ALG_CTR, sbuf + 16, 32, sbuf,
                           sizeof(sbuf), &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL oneshot stream overlap: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* Decrypt path: the mirror of the encrypt contract. In-place
     * block-mode decrypt must be rejected. */
    ct_len = 0;
    if (psa_cipher_decrypt(nopad_id, PSA_ALG_CBC_NO_PADDING, buf, 48,
                           buf, sizeof(buf), &ct_len) !=
        PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place decrypt nopad: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    ct_len = 0;
    if (psa_cipher_decrypt(pkcs7_id, PSA_ALG_CBC_PKCS7, buf, 48, buf,
                           sizeof(buf), &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place decrypt pkcs7: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* DES3 + PKCS7 decrypt overlap was uncovered too. */
    ct_len = 0;
    if (psa_cipher_decrypt(des3_id, PSA_ALG_CBC_PKCS7, buf, 48, buf,
                           sizeof(buf), &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL in-place decrypt des3-pkcs7: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* Forward overlap on the stream decrypt path: the IV sits at
     * fbuf[0..15], the CTR ciphertext at fbuf[16..79], and the output
     * starts inside the ciphertext range. Pre-fix this returned
     * SUCCESS after writing plaintext block 0 over the unread
     * ciphertext block 1. */
    for (i = 0; i < (int)sizeof(fbuf); i++) {
        fbuf[i] = (uint8_t)(i + 7);
    }
    ct_len = 0;
    if (psa_cipher_decrypt(ctr_id, PSA_ALG_CTR, fbuf, 80, fbuf + 32, 64,
                           &ct_len) != PSA_ERROR_NOT_SUPPORTED) {
        printf("FAIL forward-overlap decrypt ctr: expected NOT_SUPPORTED\n");
        rc = 1;
    }

    /* Multipart contract: block modes reject in-place updates, the
     * stream modes accept them and must match a disjoint run. */
    if (block_update_rejects_overlap(PSA_ALG_CBC_NO_PADDING, "cbcnopad") != 0) {
        rc = 1;
    }
    if (block_update_rejects_overlap(PSA_ALG_CBC_PKCS7, "cbcpkcs7") != 0) {
        rc = 1;
    }
    if (block_update_rejects_overlap(PSA_ALG_ECB_NO_PADDING, "ecb") != 0) {
        rc = 1;
    }
    if (stream_inplace_matches_reference(PSA_KEY_TYPE_AES, 128,
                                         PSA_ALG_CTR, 16, "ctr") != 0) {
        rc = 1;
    }
    if (stream_inplace_matches_reference(PSA_KEY_TYPE_AES, 128,
                                         PSA_ALG_CFB, 16, "cfb") != 0) {
        rc = 1;
    }
    if (stream_inplace_matches_reference(PSA_KEY_TYPE_AES, 128,
                                         PSA_ALG_OFB, 16, "ofb") != 0) {
        rc = 1;
    }
    if (stream_inplace_matches_reference(PSA_KEY_TYPE_AES, 128,
                                         PSA_ALG_CCM_STAR_NO_TAG, 13,
                                         "ccmstar") != 0) {
        rc = 1;
    }
    if (stream_inplace_matches_reference(PSA_KEY_TYPE_CHACHA20, 256,
                                         PSA_ALG_STREAM_CIPHER, 12,
                                         "chacha20") != 0) {
        rc = 1;
    }

    (void)psa_destroy_key(nopad_id);
    (void)psa_destroy_key(pkcs7_id);
    (void)psa_destroy_key(ctr_id);
    (void)psa_destroy_key(des3_id);

    if (rc != 0) {
        printf("PSA cipher overlap test: FAIL\n");
        return 1;
    }

    printf("PSA cipher overlap test: OK\n");
    return 0;
}
