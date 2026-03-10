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

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#ifndef INVALID_DEVID
#define INVALID_DEVID -2
#endif

#define TEST_OK 0
#define TEST_FAIL 1

typedef int (*test_fn_t)(void);

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
    static const uint8_t aad[] = { };
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
                          aad, sizeof(aad),
                          plaintext, sizeof(plaintext),
                          out, sizeof(out), &out_len);
    if (check_status(st, "psa_aead_encrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(out_len == sizeof(expected), "psa_aead_encrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_encrypt", out, expected, sizeof(expected)) != TEST_OK) return TEST_FAIL;

    st = psa_aead_decrypt(key_id, PSA_ALG_GCM,
                          nonce, sizeof(nonce),
                          aad, sizeof(aad),
                          out, out_len,
                          dec, sizeof(dec), &dec_len);
    if (check_status(st, "psa_aead_decrypt") != TEST_OK) return TEST_FAIL;
    if (check_true(dec_len == sizeof(plaintext), "psa_aead_decrypt length") != TEST_OK) return TEST_FAIL;
    if (check_buf_eq("psa_aead_decrypt", dec, plaintext, sizeof(plaintext)) != TEST_OK) return TEST_FAIL;

    st = psa_destroy_key(key_id);
    if (check_status(st, "psa_destroy_key(GCM)") != TEST_OK) return TEST_FAIL;

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

static int run_named_test(const char* name, test_fn_t fn)
{
    fprintf(stderr, "RUN %s\n", name);
    return fn();
}

int main(int argc, char** argv)
{
    psa_status_t st;
    const char* only = argc > 1 ? argv[1] : NULL;

    st = psa_crypto_init();
    if (check_status(st, "psa_crypto_init") != TEST_OK) return TEST_FAIL;

    if (only == NULL || strcmp(only, "random") == 0) {
        if (run_named_test("random", test_random) != TEST_OK) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hash") == 0) {
        if (run_named_test("hash", test_hash) != TEST_OK) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "hmac") == 0) {
        if (run_named_test("hmac", test_hmac) != TEST_OK) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "cipher_cbc") == 0) {
        if (run_named_test("cipher_cbc", test_cipher_cbc) != TEST_OK) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "aead_gcm") == 0) {
        if (run_named_test("aead_gcm", test_aead_gcm) != TEST_OK) return TEST_FAIL;
    }
    if (only == NULL || strcmp(only, "asym_ecc") == 0) {
        if (run_named_test("asym_ecc", test_asym_ecc) != TEST_OK) return TEST_FAIL;
    }

    printf("PSA API test: OK\n");
    return TEST_OK;
}
