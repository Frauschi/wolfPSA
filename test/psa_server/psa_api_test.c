/* psa_api_test.c
 * Standalone PSA API coverage test for wolfPSA.
 */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <wolfpsa/psa/crypto.h>
#include "psa_aead_internal.h"

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef INVALID_DEVID
#define INVALID_DEVID -2
#endif

#define TEST_OK 0
#define TEST_FAIL 1
#define TEST_SKIPPED 2
#define ED25519_PUBLIC_KEY_BYTES 32u
#define ED448_PUBLIC_KEY_BYTES   57u

typedef int (*test_fn_t)(void);

static int tests_passed = 0;
static int tests_skipped = 0;

static int check_status(psa_status_t st, const char* what)
{
    if (st != PSA_SUCCESS) {
        printf("FAIL: %s (status=%d)\n", what, (int)st);
        return TEST_FAIL;
    }
    return TEST_OK;
}

static int check_true(int cond, const char* what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        return TEST_FAIL;
    }
    return TEST_OK;
}

static int check_buf_eq(const char* what, const uint8_t* a, const uint8_t* b, size_t sz)
{
    if (memcmp(a, b, sz) != 0) {
        printf("FAIL: %s (mismatch)\n", what);
        return TEST_FAIL;
    }
    return TEST_OK;
}

static int test_hash(void)
{
    static const uint8_t msg[] = "abc";
    static const uint8_t expected[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t out1[WC_SHA256_DIGEST_SIZE];
    uint8_t out2[WC_SHA256_DIGEST_SIZE];
    size_t out1_len = 0;
    size_t out2_len = 0;
    psa_hash_operation_t op = psa_hash_operation_init();
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          out1, sizeof(out1), &out1_len);
    if (check_status(st, "psa_hash_compute") != TEST_OK) return TEST_FAIL;
    if (check_true(out1_len == sizeof(expected), "psa_hash_compute length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_hash_compute", out1, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (check_status(st, "psa_hash_setup") != TEST_OK) return TEST_FAIL;
    st = psa_hash_update(&op, msg, sizeof(msg) - 1);
    if (check_status(st, "psa_hash_update") != TEST_OK) return TEST_FAIL;
    st = psa_hash_finish(&op, out2, sizeof(out2), &out2_len);
    if (check_status(st, "psa_hash_finish") != TEST_OK) return TEST_FAIL;
    if (check_true(out2_len == sizeof(expected), "psa_hash_finish length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_hash_finish", out2, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_random(void)
{
    uint8_t buf[32];
    size_t i;
    int all_zero = 1;
    psa_status_t st;

    st = psa_generate_random(buf, sizeof(buf));
    if (check_status(st, "psa_generate_random") != TEST_OK) return TEST_FAIL;

    for (i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) {
            all_zero = 0;
            break;
        }
    }

    return check_true(!all_zero, "psa_generate_random non-zero");
}

static int test_hmac(void)
{
    static const uint8_t key[] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t msg[] = "hmac message";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    uint8_t out[WC_SHA256_DIGEST_SIZE];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    Hmac hmac;
    int ret;

    ret = wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_HmacInit (%d)\n", ret);
        return TEST_FAIL;
    }
    ret = wc_HmacSetKey(&hmac, WC_SHA256, key, sizeof(key));
    if (ret != 0) {
        wc_HmacFree(&hmac);
        printf("FAIL: wc_HmacSetKey (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_HmacUpdate(&hmac, msg, (word32)sizeof(msg) - 1);
    wc_HmacFinal(&hmac, expected);
    wc_HmacFree(&hmac);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, (size_t)sizeof(key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(HMAC)") != TEST_OK) return TEST_FAIL;

    st = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256),
                         msg, sizeof(msg) - 1, out, sizeof(out), &out_len);
    if (check_status(st, "psa_mac_compute") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_mac_compute length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_mac_compute", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_algorithm_none_rejects_key_usage(void)
{
    static const uint8_t aes_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t hmac_key[16] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81
    };
    static const uint8_t hash[WC_SHA256_DIGEST_SIZE] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t sig[80];
    size_t sig_len = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t cipher_op = psa_cipher_operation_init();
    psa_aead_operation_t aead_op = psa_aead_operation_init();
    psa_mac_operation_t mac_op = psa_mac_operation_init();
    psa_key_derivation_operation_t kdf_op = psa_key_derivation_operation_init();
    psa_key_id_t key_id = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(AES alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&cipher_op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_cipher_encrypt_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES cipher alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    st = psa_import_key(&attrs, aes_key, sizeof(aes_key), &key_id);
    if (check_status(st, "psa_import_key(AES AEAD alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&aead_op, key_id, PSA_ALG_GCM);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_aead_encrypt_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES AEAD alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_MESSAGE);
    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(HMAC alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_mac_sign_setup(&mac_op, key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_mac_sign_setup rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(HMAC alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH);
    st = psa_generate_key(&attrs, &key_id);
    if (check_status(st, "psa_generate_key(ECDSA alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_sign_hash(key_id, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_sign_hash rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ECDSA alg none)") != TEST_OK) {
        return TEST_FAIL;
    }
    key_id = 0;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_bits(&attrs, sizeof(hmac_key) * 8u);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    st = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), &key_id);
    if (check_status(st, "psa_import_key(DERIVE alg none)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&kdf_op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF alg none)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&kdf_op, PSA_KEY_DERIVATION_INPUT_SECRET, key_id);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_input_key rejects PSA_ALG_NONE policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&cipher_op);
    (void)psa_aead_abort(&aead_op);
    (void)psa_mac_abort(&mac_op);
    (void)psa_key_derivation_abort(&kdf_op);
    return ret;
}

static int test_cipher_cbc(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[32] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
    };
    static const uint8_t expected[sizeof(plaintext)] = {
        0x76,0x49,0xab,0xac,0x81,0x19,0xb2,0x46,
        0xce,0xe9,0x8e,0x9b,0x12,0xe9,0x19,0x7d,
        0x50,0x86,0xcb,0x9b,0x50,0x72,0x19,0xee,
        0x95,0xdb,0x11,0x3a,0x91,0x76,0x78,0xb2
    };
    uint8_t out[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext) + 16];
    size_t out_len = 0;
    size_t finish_len = 0;
    size_t dec_len = 0;
    size_t dec_finish_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES)") != TEST_OK) return TEST_FAIL;

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_encrypt_setup") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext), out, sizeof(out), &out_len);
    if (check_status(st, "psa_cipher_update") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_finish(&op, out + out_len, sizeof(out) - out_len, &finish_len);
    if (check_status(st, "psa_cipher_finish") != TEST_OK) return TEST_FAIL;
    out_len += finish_len;

    if (check_true(out_len == sizeof(expected), "psa_cipher_encrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_cipher_encrypt", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_NO_PADDING);
    if (check_status(st, "psa_cipher_decrypt_setup") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(dec)") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_update(&op, out, out_len, dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_cipher_update(dec)") != TEST_OK) return TEST_FAIL;
    st = psa_cipher_finish(&op, dec + dec_len, sizeof(dec) - dec_len, &dec_finish_len);
    if (check_status(st, "psa_cipher_finish(dec)") != TEST_OK) return TEST_FAIL;
    dec_len += dec_finish_len;

    if (check_true(dec_len == sizeof(plaintext), "psa_cipher_decrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_cipher_decrypt", dec, plaintext, sizeof(plaintext)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_cipher_rejects_algorithm_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES CBC policy)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CTR);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_cipher_encrypt_setup rejects mismatched algorithm policy") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    (void)psa_cipher_abort(&op);
    return ret;
}

static int test_export_key_requires_usage_flag(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES no export)") != TEST_OK) return TEST_FAIL;

    st = psa_export_key(key_id, exported, sizeof(exported), &exported_len);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_export_key requires PSA_KEY_USAGE_EXPORT") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES no export)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static void setup_aes_key_attrs(psa_key_attributes_t* attrs, psa_key_usage_t usage,
                                psa_algorithm_t alg, psa_key_lifetime_t lifetime)
{
    *attrs = psa_key_attributes_init();
    psa_set_key_type(attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(attrs, 128);
    psa_set_key_usage_flags(attrs, usage);
    psa_set_key_algorithm(attrs, alg);
    psa_set_key_lifetime(attrs, lifetime);
}

static int test_copy_key_copies_material_and_attributes(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t exported[sizeof(key)];
    size_t exported_len = 0;
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = 0;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_key_attributes_t got_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES copy source)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_status(st, "psa_copy_key(success)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(copy_key != src_key, "psa_copy_key returns a new key id") != TEST_OK) {
        goto cleanup;
    }

    st = psa_export_key(copy_key, exported, sizeof(exported), &exported_len);
    if (check_status(st, "psa_export_key(copied AES)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(exported_len == sizeof(key), "psa_export_key(copied AES) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_export_key(copied AES)", exported, key, sizeof(key)) != TEST_OK) {
        goto cleanup;
    }

    st = psa_get_key_attributes(copy_key, &got_attrs);
    if (check_status(st, "psa_get_key_attributes(copied AES)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_type(&got_attrs) == PSA_KEY_TYPE_AES,
                   "psa_copy_key preserves type") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_bits(&got_attrs) == 128,
                   "psa_copy_key preserves bits") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_algorithm(&got_attrs) == PSA_ALG_CBC_NO_PADDING,
                   "psa_copy_key preserves algorithm") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_lifetime(&got_attrs) == PSA_KEY_LIFETIME_VOLATILE,
                   "psa_copy_key preserves lifetime") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(psa_get_key_usage_flags(&got_attrs) ==
                   (PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT),
                   "psa_copy_key intersects usage flags") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&got_attrs);
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != 0) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_requires_copy_usage_flag(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES no copy)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_copy_key requires PSA_KEY_USAGE_COPY for volatile keys") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_rejects_attribute_mismatch(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_COPY | PSA_KEY_USAGE_EXPORT |
                        PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES copy mismatch source)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&dst_attrs, PSA_KEY_TYPE_DES);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects type mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_bits(&dst_attrs, 192);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects bit-size mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_ECB_NO_PADDING,
                        PSA_KEY_LIFETIME_VOLATILE);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects algorithm mismatch") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_copy_key rejects lifetime mismatch") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_copy_key_requires_copy_usage_flag_persistent(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    psa_key_id_t src_key = 0;
    psa_key_id_t copy_key = PSA_KEY_ID_NULL;
    psa_key_id_t persistent_id = PSA_KEY_ID_USER_MIN + 2405u;
    psa_key_attributes_t src_attrs = psa_key_attributes_init();
    psa_key_attributes_t dst_attrs = psa_key_attributes_init();
    psa_status_t st;
    int ret = TEST_FAIL;

    (void)psa_destroy_key(persistent_id);

    setup_aes_key_attrs(&src_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&src_attrs, persistent_id);
    st = psa_import_key(&src_attrs, key, sizeof(key), &src_key);
    if (check_status(st, "psa_import_key(AES persistent no copy)") != TEST_OK) {
        goto cleanup;
    }

    setup_aes_key_attrs(&dst_attrs,
                        PSA_KEY_USAGE_EXPORT | PSA_KEY_USAGE_ENCRYPT,
                        PSA_ALG_CBC_NO_PADDING,
                        PSA_KEY_LIFETIME_PERSISTENT);
    st = psa_copy_key(src_key, &dst_attrs, &copy_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_copy_key requires PSA_KEY_USAGE_COPY for persistent keys") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    psa_reset_key_attributes(&dst_attrs);
    psa_reset_key_attributes(&src_attrs);
    if (copy_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(copy_key);
    }
    if (src_key != 0) {
        (void)psa_destroy_key(src_key);
    }
    return ret;
}

static int test_cipher_cbc_pkcs7_multipart_decrypt(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[17] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67
    };
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t decrypted[sizeof(plaintext)];
    size_t ciphertext_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t dec_len = 0;
    size_t dec_part_len = 0;
    size_t dec_finish_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;
    int result = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES PKCS7)") != TEST_OK) goto cleanup;

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        result = TEST_SKIPPED;
        goto cleanup;
    }
    if (check_status(st, "psa_cipher_encrypt_setup(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext), &part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += part_len;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 enc)") != TEST_OK) {
        goto cleanup;
    }
    ciphertext_len += finish_len;
    (void)psa_cipher_abort(&op);

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_decrypt_setup(PKCS7)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 dec)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_update(&op, ciphertext, 1,
                           decrypted, sizeof(decrypted), &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec 1)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 0, "psa_cipher_update(PKCS7 dec 1) length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_update(&op, ciphertext + 1, 16,
                           decrypted, sizeof(decrypted), &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec 16)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 16, "psa_cipher_update(PKCS7 dec 16) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_update(PKCS7 dec 16)",
                     decrypted, plaintext, dec_part_len) != TEST_OK) {
        goto cleanup;
    }
    dec_len += dec_part_len;

    st = psa_cipher_update(&op, ciphertext + 17, ciphertext_len - 17,
                           decrypted + dec_len, sizeof(decrypted) - dec_len,
                           &dec_part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 dec tail)") != TEST_OK) {
        goto cleanup;
    }
    if (check_true(dec_part_len == 0, "psa_cipher_update(PKCS7 dec tail) length") != TEST_OK) {
        goto cleanup;
    }

    st = psa_cipher_finish(&op, decrypted + dec_len, sizeof(decrypted) - dec_len,
                           &dec_finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 dec)") != TEST_OK) {
        goto cleanup;
    }
    dec_len += dec_finish_len;
    (void)psa_cipher_abort(&op);

    if (check_true(dec_len == sizeof(plaintext), "psa_cipher_decrypt(PKCS7) length") != TEST_OK) {
        goto cleanup;
    }
    if (check_buf_eq("psa_cipher_decrypt(PKCS7)", decrypted, plaintext, sizeof(plaintext)) != TEST_OK) {
        goto cleanup;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES PKCS7)") != TEST_OK) return TEST_FAIL;

    key_id = 0;
    result = TEST_OK;

cleanup:
    (void)psa_cipher_abort(&op);
    if (key_id != 0) {
        (void)psa_destroy_key(key_id);
    }
    return result;
}

static int test_cipher_cbc_pkcs7_decrypt_update_small_output(void)
{
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t plaintext[17] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66,
        0x67
    };
    uint8_t ciphertext[sizeof(plaintext) + 16];
    uint8_t too_small[1];
    size_t ciphertext_len = 0;
    size_t part_len = 0;
    size_t finish_len = 0;
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_cipher_operation_t op = psa_cipher_operation_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_CBC_PKCS7);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES PKCS7 small out)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_cipher_encrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_encrypt_setup(PKCS7 small out)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_update(&op, plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext), &part_len);
    if (check_status(st, "psa_cipher_update(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    ciphertext_len += part_len;
    st = psa_cipher_finish(&op, ciphertext + ciphertext_len,
                           sizeof(ciphertext) - ciphertext_len, &finish_len);
    if (check_status(st, "psa_cipher_finish(PKCS7 small out enc)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    ciphertext_len += finish_len;

    op = psa_cipher_operation_init();
    st = psa_cipher_decrypt_setup(&op, key_id, PSA_ALG_CBC_PKCS7);
    if (check_status(st, "psa_cipher_decrypt_setup(PKCS7 small out)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    st = psa_cipher_set_iv(&op, iv, sizeof(iv));
    if (check_status(st, "psa_cipher_set_iv(PKCS7 small out dec)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_cipher_update(&op, ciphertext, 1, too_small, sizeof(too_small), &out_len);
    if (check_status(st, "psa_cipher_update(PKCS7 small out seed)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(out_len == 0,
                   "psa_cipher_update(PKCS7 small out seed) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_cipher_update(&op, ciphertext + 1, 16, too_small, sizeof(too_small), &out_len);
    if (check_true(st == PSA_ERROR_BUFFER_TOO_SMALL,
                   "psa_cipher_update(PKCS7 small out status)") != TEST_OK) {
        (void)psa_cipher_abort(&op);
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    (void)psa_cipher_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES PKCS7 small out)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_aead_gcm(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t aad[1] = { 0 };
    static const size_t aad_len = 0;
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t expected[sizeof(plaintext) + 16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,
        0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78,
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,
        0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf
    };
    uint8_t out[sizeof(plaintext) + 16];
    uint8_t dec[sizeof(plaintext)];
    size_t out_len = 0;
    size_t dec_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, aad_len,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_status(st, "psa_aead_encrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_aead_encrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_encrypt", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, aad_len,
                          out, out_len,
                          dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_aead_decrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(dec_len == sizeof(plaintext), "psa_aead_decrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_decrypt", dec, plaintext, sizeof(plaintext)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_aead_multipart_length_overflow_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t chunk[2] = { 0xaa, 0x55 };
    uint8_t out[sizeof(chunk)];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    wolfpsa_aead_ctx_t *ctx;
    int ret = TEST_OK;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM overflow)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup") != TEST_OK) goto cleanup;
    st = psa_aead_set_lengths(&op, SIZE_MAX, SIZE_MAX);
    if (check_status(st, "psa_aead_set_lengths") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce") != TEST_OK) goto cleanup;

    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad_length = SIZE_MAX - 1;
    st = psa_aead_update_ad(&op, chunk, sizeof(chunk));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_update_ad rejects wrapped accumulated length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(plaintext)") != TEST_OK) goto cleanup;
    st = psa_aead_set_lengths(&op, 0, SIZE_MAX);
    if (check_status(st, "psa_aead_set_lengths(plaintext)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(plaintext)") != TEST_OK) goto cleanup;

    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input_length = SIZE_MAX - 1;
    st = psa_aead_update(&op, chunk, sizeof(chunk), out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_update rejects wrapped accumulated length") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM overflow)") != TEST_OK) return TEST_FAIL;
    return ret;
}

static int test_aead_finish_verify_word32_overflow_rejected(void)
{
    static const uint8_t key[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t empty_gcm_tag[16] = {
        0x58,0xe2,0xfc,0xce,0xfa,0x7e,0x30,0x61,
        0x36,0x7f,0x1d,0x57,0xa4,0xe7,0x45,0x5a
    };
    uint8_t out[1];
    uint8_t tag[sizeof(empty_gcm_tag)];
    size_t out_len = 0;
    size_t tag_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_aead_operation_t op = psa_aead_operation_init();
    wolfpsa_aead_ctx_t *ctx;
    int ret = TEST_OK;
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(GCM word32 overflow)") != TEST_OK) {
        return TEST_FAIL;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(word32 input)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 input)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input = NULL;
    ctx->input_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_finish(&op, out, SIZE_MAX, &out_len, tag, sizeof(tag), &tag_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_finish rejects input_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_encrypt_setup(word32 aad)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 aad)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad = NULL;
    ctx->aad_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_finish(&op, out, sizeof(out), &out_len, tag, sizeof(tag), &tag_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_finish rejects aad_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(word32 input)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 verify input)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->input = NULL;
    ctx->input_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_verify(&op, out, SIZE_MAX, &out_len, empty_gcm_tag, sizeof(empty_gcm_tag));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_verify rejects input_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

    st = psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM);
    if (check_status(st, "psa_aead_decrypt_setup(word32 aad)") != TEST_OK) goto cleanup;
    st = psa_aead_set_nonce(&op, nonce, sizeof(nonce));
    if (check_status(st, "psa_aead_set_nonce(word32 verify aad)") != TEST_OK) goto cleanup;
    ctx = wolfpsa_aead_get_ctx_ptr(&op);
    ctx->aad = NULL;
    ctx->aad_length = (size_t)UINT32_MAX + 1u;
    st = psa_aead_verify(&op, out, sizeof(out), &out_len, empty_gcm_tag, sizeof(empty_gcm_tag));
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_verify rejects aad_length above word32") != TEST_OK) {
        ret = TEST_FAIL;
        goto cleanup;
    }

cleanup:
    psa_aead_abort(&op);
    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM word32 overflow)") != TEST_OK) {
        return TEST_FAIL;
    }
    return ret;
}

static int test_chacha20_poly1305_rejects_aes_key(void)
{
    static const uint8_t key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const uint8_t nonce[12] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
    };
    static const uint8_t plaintext[16] = {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    uint8_t out[sizeof(plaintext) + 16];
    size_t out_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attrs, PSA_ALG_GCM);

    /*
     * Import a valid AES AEAD key first, then prove that the ChaCha20-Poly1305
     * path rejects it when the operation algorithm does not match the key type.
     */
    st = psa_import_key(&attrs, key, sizeof(key), &key_id);
    if (check_status(st, "psa_import_key(AES for GCM)") != TEST_OK) return TEST_FAIL;

    st = psa_aead_encrypt(key_id, PSA_ALG_CHACHA20_POLY1305,
                          nonce, sizeof(nonce),
                          NULL, 0,
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_aead_encrypt(AES key with ChaCha20) rejected") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(AES for GCM)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_asym_ecc(void)
{
    static const uint8_t msg[] = "psa ecc sign";
    uint8_t hash[WC_SHA256_DIGEST_SIZE];
    uint8_t sig[128];
    size_t sig_len = 0;
    uint8_t pub[128];
    size_t pub_len = 0;
    psa_key_id_t sign_key = 0;
    psa_key_id_t dh_key1 = 0;
    psa_key_id_t dh_key2 = 0;
    uint8_t dh_pub1[128];
    uint8_t dh_pub2[128];
    size_t dh_pub1_len = 0;
    size_t dh_pub2_len = 0;
    uint8_t dh_out1[128];
    uint8_t dh_out2[128];
    size_t dh_out1_len = 0;
    size_t dh_out2_len = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;
    wc_Sha256 sha;
    int ret;

    ret = wc_InitSha256(&sha);
    if (ret != 0) {
        printf("FAIL: wc_InitSha256 (ecc) (%d)\n", ret);
        return TEST_FAIL;
    }
    wc_Sha256Update(&sha, msg, (word32)sizeof(msg) - 1);
    wc_Sha256Final(&sha, hash);
    wc_Sha256Free(&sha);

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attrs, &sign_key);
    if (check_status(st, "psa_generate_key(ECDSA)") != TEST_OK) return TEST_FAIL;

    st = psa_sign_hash(sign_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       hash, sizeof(hash), sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash") != TEST_OK) return TEST_FAIL;

    st = psa_verify_hash(sign_key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                         hash, sizeof(hash), sig, sig_len);
    if (check_status(st, "psa_verify_hash") != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(sign_key, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key") != TEST_OK) return TEST_FAIL;
    if (check_true(pub_len > 0, "psa_export_public_key length") != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(sign_key);
    if (check_status(st, "psa_destroy_key(ECDSA)") != TEST_OK) return TEST_FAIL;

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    st = psa_generate_key(&attrs, &dh_key1);
    if (check_status(st, "psa_generate_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_generate_key(&attrs, &dh_key2);
    if (check_status(st, "psa_generate_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(dh_key1, dh_pub1, sizeof(dh_pub1), &dh_pub1_len);
    if (check_status(st, "psa_export_public_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_export_public_key(dh_key2, dh_pub2, sizeof(dh_pub2), &dh_pub2_len);
    if (check_status(st, "psa_export_public_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    st = psa_raw_key_agreement(PSA_ALG_ECDH, dh_key1, dh_pub2, dh_pub2_len,
                               dh_out1, sizeof(dh_out1), &dh_out1_len);
    if (check_status(st, "psa_raw_key_agreement(1)") != TEST_OK) return TEST_FAIL;
    st = psa_raw_key_agreement(PSA_ALG_ECDH, dh_key2, dh_pub1, dh_pub1_len,
                               dh_out2, sizeof(dh_out2), &dh_out2_len);
    if (check_status(st, "psa_raw_key_agreement(2)") != TEST_OK) return TEST_FAIL;

    if (check_true(dh_out1_len == dh_out2_len, "psa_raw_key_agreement length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_raw_key_agreement", dh_out1, dh_out2, dh_out1_len) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(dh_key1);
    if (check_status(st, "psa_destroy_key(ECDH1)") != TEST_OK) return TEST_FAIL;
    st = psa_destroy_key(dh_key2);
    if (check_status(st, "psa_destroy_key(ECDH2)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_ed25519_signature_length(void)
{
    static const uint8_t hash[64] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
    };
    static const uint8_t msg[] = "ed25519 message dispatch";
    uint8_t sig[128];
    /*
     * The original bug cast `size_t*` to `word32*`. On 64-bit builds that can
     * update only the low 32 bits, leaving the upper 32 bits stale. Seed
     * `sig_len` with the low half clear and the upper half all ones so a
     * truncated store becomes a large non-64 value instead of accidentally
     * looking correct.
     */
    size_t sig_len = ~((size_t)UINT32_MAX);
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, 255);
    psa_set_key_usage_flags(&attrs,
        PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH |
        PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ED25519PH);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, "psa_generate_key(ED25519)") != TEST_OK) return TEST_FAIL;

    st = psa_sign_hash(key_id, PSA_ALG_ED25519PH,
                       hash, sizeof(hash),
                       sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_hash(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(sig_len == 64u, "psa_sign_hash(ED25519PH) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_hash(key_id, PSA_ALG_ED25519PH,
                         hash, sizeof(hash), sig, sig_len);
    if (check_status(st, "psa_verify_hash(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    sig_len = sizeof(sig);
    st = psa_sign_message(key_id, PSA_ALG_ED25519PH,
                          msg, sizeof(msg) - 1,
                          sig, sizeof(sig), &sig_len);
    if (check_status(st, "psa_sign_message(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(sig_len == 64u, "psa_sign_message(ED25519PH) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_verify_message(key_id, PSA_ALG_ED25519PH,
                            msg, sizeof(msg) - 1, sig, sig_len);
    if (check_status(st, "psa_verify_message(ED25519PH)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(ED25519)") != TEST_OK) return TEST_FAIL;

    return TEST_OK;
}

static int test_twisted_edwards_export_public_key(size_t bits,
                                                  psa_algorithm_t alg,
                                                  size_t expected_pub_len,
                                                  const char* label)
{
    uint8_t pub[ED448_PUBLIC_KEY_BYTES];
    size_t pub_len = 0;
    psa_key_id_t key_id = 0;
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t st;

    psa_set_key_type(&attrs,
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, alg);

    st = psa_generate_key(&attrs, &key_id);
    if (st == PSA_ERROR_NOT_SUPPORTED) {
        return TEST_SKIPPED;
    }
    if (check_status(st, label) != TEST_OK) return TEST_FAIL;

    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (check_status(st, "psa_export_public_key(Twisted Edwards)") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }
    if (check_true(pub_len == expected_pub_len,
                   "psa_export_public_key(Twisted Edwards) length") != TEST_OK) {
        (void)psa_destroy_key(key_id);
        return TEST_FAIL;
    }

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(Twisted Edwards)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_ed25519_export_public_key(void)
{
    return test_twisted_edwards_export_public_key(255, PSA_ALG_ED25519PH,
                                                  ED25519_PUBLIC_KEY_BYTES,
                                                  "psa_generate_key(ED25519 export)");
}

static int test_ed448_export_public_key(void)
{
    return test_twisted_edwards_export_public_key(448, PSA_ALG_ED448PH,
                                                  ED448_PUBLIC_KEY_BYTES,
                                                  "psa_generate_key(ED448 export)");
}

static int test_kdf_null_capacity(void)
{
    size_t capacity = 0;
    psa_status_t st;

    st = psa_key_derivation_get_capacity(NULL, &capacity);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_get_capacity(NULL)") != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_input_key_policy(void)
{
    static const uint8_t secret[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const uint8_t info[] = "kdf-input-key";
    uint8_t output[16];
    size_t output_len = 0;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_id_t derive_key = 0;
    psa_key_id_t no_usage_key = 0;
    psa_key_id_t raw_key = 0;
    psa_key_id_t password_key = 0;
    psa_key_id_t wrong_pbkdf2_key = 0;
    psa_status_t st;
    int ret = TEST_FAIL;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &derive_key);
    if (check_status(st, "psa_import_key(KDF derive key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF input key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, derive_key);
    if (check_status(st, "psa_key_derivation_input_key(HKDF derive key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO input key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(input key)") != TEST_OK) {
        goto cleanup;
    }
    output_len = sizeof(output);
    if (check_true(output_len == sizeof(output),
                   "psa_key_derivation_output_bytes(input key) length") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF input key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &no_usage_key);
    if (check_status(st, "psa_import_key(KDF no usage key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF no usage)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, no_usage_key);
    if (check_true(st == PSA_ERROR_NOT_PERMITTED,
                   "psa_key_derivation_input_key rejects missing DERIVE usage") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF no usage)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &raw_key);
    if (check_status(st, "psa_import_key(KDF raw key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF raw key)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, raw_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_input_key rejects non-DERIVE secret key type") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF raw key)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_PASSWORD);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &password_key);
    if (check_status(st, "psa_import_key(PBKDF2 password key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password_key);
    if (check_status(st, "psa_key_derivation_input_key(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(PBKDF2 password)") != TEST_OK) {
        goto cleanup;
    }
    op = psa_key_derivation_operation_init();

    psa_reset_key_attributes(&attrs);
    psa_set_key_type(&attrs, PSA_KEY_TYPE_DERIVE);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    st = psa_import_key(&attrs, secret, sizeof(secret), &wrong_pbkdf2_key);
    if (check_status(st, "psa_import_key(PBKDF2 wrong type key)") != TEST_OK) {
        goto cleanup;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(PBKDF2 wrong type)") != TEST_OK) {
        goto cleanup;
    }
    st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_PASSWORD,
                                      wrong_pbkdf2_key);
    if (check_true(st == PSA_ERROR_INVALID_ARGUMENT,
                   "psa_key_derivation_input_key rejects non-PASSWORD PBKDF2 key type") != TEST_OK) {
        goto cleanup;
    }

    ret = TEST_OK;

cleanup:
    (void)psa_key_derivation_abort(&op);
    if (wrong_pbkdf2_key != 0) {
        (void)psa_destroy_key(wrong_pbkdf2_key);
    }
    if (password_key != 0) {
        (void)psa_destroy_key(password_key);
    }
    if (raw_key != 0) {
        (void)psa_destroy_key(raw_key);
    }
    if (no_usage_key != 0) {
        (void)psa_destroy_key(no_usage_key);
    }
    if (derive_key != 0) {
        (void)psa_destroy_key(derive_key);
    }
    psa_reset_key_attributes(&attrs);
    return ret;
}

static int test_kdf_tls12_psk_to_ms_rfc4279_order(void)
{
    static const uint8_t psk[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5 };
    static const uint8_t other_secret[] = { 0x10, 0x20, 0x30 };
    static const uint8_t seed[] = "clienthello||serverhello";
    uint8_t premaster[2u + sizeof(other_secret) + 2u + sizeof(psk)];
    uint8_t expected[48];
    uint8_t output[sizeof(expected)];
    size_t seed_len = sizeof(seed) - 1u;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    premaster[0] = 0x00;
    premaster[1] = (uint8_t)sizeof(other_secret);
    memcpy(premaster + 2u, other_secret, sizeof(other_secret));
    premaster[2u + sizeof(other_secret)] = 0x00;
    premaster[3u + sizeof(other_secret)] = (uint8_t)sizeof(psk);
    memcpy(premaster + 4u + sizeof(other_secret), psk, sizeof(psk));

    ret = wc_PRF_TLS(expected, (word32)sizeof(expected),
                     premaster, (word32)sizeof(premaster),
                     (const byte*)"master secret", 13u,
                     seed, (word32)seed_len,
                     1, WC_HASH_TYPE_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_PRF_TLS(TLS12_PSK_TO_MS reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(TLS12_PSK_TO_MS)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SEED,
                                        seed, seed_len);
    if (check_status(st, "psa_key_derivation_input_bytes(SEED)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op,
                                        PSA_KEY_DERIVATION_INPUT_OTHER_SECRET,
                                        other_secret, sizeof(other_secret));
    if (check_status(st, "psa_key_derivation_input_bytes(OTHER_SECRET)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        psk, sizeof(psk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(TLS12_PSK_TO_MS)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(TLS12_PSK_TO_MS)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(TLS12_PSK_TO_MS RFC4279)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_tls12_psk_to_ms_plain_psk_optional_other_secret(void)
{
    static const uint8_t psk[] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5 };
    static const uint8_t seed[] = "clienthello||serverhello";
    uint8_t premaster[2u + sizeof(psk) + 2u + sizeof(psk)];
    uint8_t expected[48];
    uint8_t output[sizeof(expected)];
    size_t seed_len = sizeof(seed) - 1u;
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    premaster[0] = 0x00;
    premaster[1] = (uint8_t)sizeof(psk);
    memset(premaster + 2u, 0, sizeof(psk));
    premaster[2u + sizeof(psk)] = 0x00;
    premaster[3u + sizeof(psk)] = (uint8_t)sizeof(psk);
    memcpy(premaster + 4u + sizeof(psk), psk, sizeof(psk));

    ret = wc_PRF_TLS(expected, (word32)sizeof(expected),
                     premaster, (word32)sizeof(premaster),
                     (const byte*)"master secret", 13u,
                     seed, (word32)seed_len,
                     1, WC_HASH_TYPE_SHA256, NULL, INVALID_DEVID);
    if (ret != 0) {
        printf("FAIL: wc_PRF_TLS(TLS12_PSK_TO_MS plain PSK reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_TLS12_PSK_TO_MS(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SEED,
                                        seed, seed_len);
    if (check_status(st, "psa_key_derivation_input_bytes(SEED plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        psk, sizeof(psk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(TLS12_PSK_TO_MS plain PSK)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(TLS12_PSK_TO_MS plain PSK RFC4279)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_extract_optional_salt(void)
{
    static const uint8_t secret[] = "hkdf extract secret";
    uint8_t expected[WC_SHA256_DIGEST_SIZE];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Extract(WC_HASH_TYPE_SHA256,
                          NULL, 0,
                          secret, (word32)(sizeof(secret) - 1u),
                          expected);
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Extract(HKDF_EXTRACT optional salt reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXTRACT optional salt)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(SALT HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF_EXTRACT optional salt)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF_EXTRACT optional salt)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF_EXTRACT optional salt)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_expand_optional_info(void)
{
    static const uint8_t prk[WC_SHA256_DIGEST_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t expected[42];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF_Expand(WC_HASH_TYPE_SHA256,
                         prk, (word32)sizeof(prk),
                         NULL, 0,
                         expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF_Expand(HKDF_EXPAND optional info reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF_EXPAND optional info)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        prk, sizeof(prk));
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF_EXPAND optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF_EXPAND optional info)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF_EXPAND optional info)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_hkdf_optional_info(void)
{
    static const uint8_t secret[] = "hkdf secret";
    uint8_t expected[42];
    uint8_t output[sizeof(expected)];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF(WC_HASH_TYPE_SHA256,
                  secret, (word32)(sizeof(secret) - 1u),
                  NULL, 0,
                  NULL, 0,
                  expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF(HKDF optional info reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF optional info)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, NULL, 0);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output, sizeof(output));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF optional info)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF optional info)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF optional info)",
                     output, expected, sizeof(expected)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int test_kdf_output_bytes_are_sequential(void)
{
    static const uint8_t secret[] = "hkdf sequential output secret";
    static const uint8_t info[] = "hkdf sequential output info";
    uint8_t expected[32];
    uint8_t output_part1[16];
    uint8_t output_part2[16];
    psa_key_derivation_operation_t op = psa_key_derivation_operation_init();
    psa_status_t st;
    int ret;

    ret = wc_HKDF(WC_HASH_TYPE_SHA256,
                  secret, (word32)(sizeof(secret) - 1u),
                  NULL, 0,
                  info, (word32)(sizeof(info) - 1u),
                  expected, (word32)sizeof(expected));
    if (ret != 0) {
        printf("FAIL: wc_HKDF(sequential output reference) (%d)\n", ret);
        return TEST_FAIL;
    }

    st = psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256));
    if (check_status(st, "psa_key_derivation_setup(HKDF sequential output)") != TEST_OK) {
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET,
                                        secret, sizeof(secret) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(SECRET HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                        info, sizeof(info) - 1u);
    if (check_status(st, "psa_key_derivation_input_bytes(INFO HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_set_capacity(&op, sizeof(expected));
    if (check_status(st, "psa_key_derivation_set_capacity(HKDF sequential output)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output_part1, sizeof(output_part1));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF sequential output first)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_output_bytes(&op, output_part2, sizeof(output_part2));
    if (check_status(st, "psa_key_derivation_output_bytes(HKDF sequential output second)") != TEST_OK) {
        (void)psa_key_derivation_abort(&op);
        return TEST_FAIL;
    }
    st = psa_key_derivation_abort(&op);
    if (check_status(st, "psa_key_derivation_abort(HKDF sequential output)") != TEST_OK) {
        return TEST_FAIL;
    }

    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF sequential output first)",
                     output_part1, expected, sizeof(output_part1)) != TEST_OK) {
        return TEST_FAIL;
    }
    if (check_buf_eq("psa_key_derivation_output_bytes(HKDF sequential output second)",
                     output_part2, expected + sizeof(output_part1),
                     sizeof(output_part2)) != TEST_OK) {
        return TEST_FAIL;
    }

    return TEST_OK;
}

static int run_named_test(const char* name, test_fn_t fn)
{
    int ret;

    fprintf(stderr, "RUN %s\n", name);
    ret = fn();
    if (ret == TEST_OK) {
        tests_passed++;
    }
    else if (ret == TEST_SKIPPED) {
        tests_skipped++;
        fprintf(stderr, "SKIP %s\n", name);
    }
    return ret;
}

int main(int argc, char** argv)
{
    psa_status_t st;
    const char* only = argc > 1 ? argv[1] : NULL;

    st = psa_crypto_init();
    if (check_status(st, "psa_crypto_init") != TEST_OK) return TEST_FAIL;

    if (only == NULL || strcmp(only, "random") == 0) {
        if (run_named_test("random", test_random) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hash") == 0) {
        if (run_named_test("hash", test_hash) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hmac") == 0) {
        if (run_named_test("hmac", test_hmac) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "alg_none_policy") == 0) {
        if (run_named_test("alg_none_policy",
                           test_algorithm_none_rejects_key_usage) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc") == 0) {
        if (run_named_test("cipher_cbc", test_cipher_cbc) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "cipher_algorithm_mismatch") == 0) {
        if (run_named_test("cipher_algorithm_mismatch",
                           test_cipher_rejects_algorithm_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "export_requires_usage") == 0) {
        if (run_named_test("export_requires_usage",
                           test_export_key_requires_usage_flag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_success") == 0) {
        if (run_named_test("copy_key_success",
                           test_copy_key_copies_material_and_attributes) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_requires_usage") == 0) {
        if (run_named_test("copy_key_requires_usage",
                           test_copy_key_requires_copy_usage_flag) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_attribute_mismatch") == 0) {
        if (run_named_test("copy_key_attribute_mismatch",
                           test_copy_key_rejects_attribute_mismatch) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "copy_key_persistent_requires_usage") == 0) {
        if (run_named_test("copy_key_persistent_requires_usage",
                           test_copy_key_requires_copy_usage_flag_persistent) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc_pkcs7_multipart") == 0) {
        if (run_named_test("cipher_cbc_pkcs7_multipart",
                           test_cipher_cbc_pkcs7_multipart_decrypt) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "cipher_cbc_pkcs7_small_output") == 0) {
        if (run_named_test("cipher_cbc_pkcs7_small_output",
                           test_cipher_cbc_pkcs7_decrypt_update_small_output) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_gcm") == 0) {
        if (run_named_test("aead_gcm", test_aead_gcm) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "aead_multipart_length_overflow") == 0) {
        if (run_named_test("aead_multipart_length_overflow",
                           test_aead_multipart_length_overflow_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "aead_word32_overflow") == 0) {
        if (run_named_test("aead_word32_overflow",
                           test_aead_finish_verify_word32_overflow_rejected) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "chacha20_aes_reject") == 0) {
        if (run_named_test("chacha20_aes_reject",
                           test_chacha20_poly1305_rejects_aes_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "asym_ecc") == 0) {
        if (run_named_test("asym_ecc", test_asym_ecc) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "ed25519_sig_len") == 0) {
        if (run_named_test("ed25519_sig_len", test_ed25519_signature_length) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed25519_export_pub") == 0) {
        if (run_named_test("ed25519_export_pub", test_ed25519_export_public_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "ed448_export_pub") == 0) {
        if (run_named_test("ed448_export_pub", test_ed448_export_public_key) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_null_capacity") == 0) {
        if (run_named_test("kdf_null_capacity", test_kdf_null_capacity) == TEST_FAIL) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "kdf_input_key_policy") == 0) {
        if (run_named_test("kdf_input_key_policy", test_kdf_input_key_policy) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_tls12_psk_to_ms") == 0) {
        if (run_named_test("kdf_tls12_psk_to_ms",
                           test_kdf_tls12_psk_to_ms_rfc4279_order) == TEST_FAIL) {
            return TEST_FAIL;
        }
        if (run_named_test("kdf_tls12_psk_to_ms_plain_psk",
                           test_kdf_tls12_psk_to_ms_plain_psk_optional_other_secret) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_extract_optional_salt") == 0) {
        if (run_named_test("kdf_hkdf_extract_optional_salt",
                           test_kdf_hkdf_extract_optional_salt) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_expand_optional_info") == 0) {
        if (run_named_test("kdf_hkdf_expand_optional_info",
                           test_kdf_hkdf_expand_optional_info) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_hkdf_optional_info") == 0) {
        if (run_named_test("kdf_hkdf_optional_info",
                           test_kdf_hkdf_optional_info) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }
    if (only == NULL || strcmp(only, "kdf_output_bytes_are_sequential") == 0) {
        if (run_named_test("kdf_output_bytes_are_sequential",
                           test_kdf_output_bytes_are_sequential) == TEST_FAIL) {
            return TEST_FAIL;
        }
    }

    printf("PSA API test: OK (passed=%d skipped=%d)\n",
           tests_passed, tests_skipped);
    return TEST_OK;
}
