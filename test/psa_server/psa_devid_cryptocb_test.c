/* psa_devid_cryptocb_test.c
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

/*
 * Checks that every algorithm family reaches a registered crypto callback,
 * both through wolfCrypt's own device selection and through an explicit
 * wolfPSA_SetDefaultDevID().
 *
 * The probe device deliberately sits on a non-zero devId: an algorithm that
 * skipped its wc_*Init() call carries devId 0 from its zeroed context and
 * would go missing from the counts.
 *
 * Unlike the other tests here this one inspects wolfCrypt structures, so it
 * must build against the same user_settings.h as the library itself.
 */

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfpsa/psa/crypto.h>
#include <wolfpsa/psa_engine.h>

#include <stdio.h>
#include <string.h>

/* Arbitrary devId standing in for an offload backend. */
#define TEST_DEVID 0x505341

/* Registered first, so wolfCrypt's own selection picks it when wolfPSA has
 * no explicit devId. Non-zero on purpose, see the note above. */
#define PROBE_DEVID 5

static int seen[WC_ALGO_TYPE_MAX + 1];
static int seen_total;
static int seen_wrong_devid;
static int expect_devid = INVALID_DEVID;

/* When set, the callback claims AES key wrap and unwrap succeeded without
 * writing an output length. That is the bring-up mistake wolfPSA has to
 * report as a failure rather than as a zero-length success. */
static int mute_keywrap;

static const char *algo_name(int algo_type)
{
    switch (algo_type) {
        case WC_ALGO_TYPE_HASH:   return "hash";
        case WC_ALGO_TYPE_CIPHER: return "cipher";
        case WC_ALGO_TYPE_PK:     return "pk";
        case WC_ALGO_TYPE_RNG:    return "rng";
        case WC_ALGO_TYPE_SEED:   return "seed";
        case WC_ALGO_TYPE_HMAC:   return "hmac";
        case WC_ALGO_TYPE_CMAC:   return "cmac";
        default:                  return "other";
    }
}

/* Sink for the borrowed HMAC key, so the read below is not optimised away. */
static volatile byte key_sink;

/* Records the dispatch and declines it, so wolfCrypt falls back to software
 * and the PSA results stay correct.
 *
 * The HMAC arm reads the key the way a real backend would. wc_HmacSetKey()
 * stores the caller's buffer in Hmac.keyRaw rather than copying it, so this
 * is what catches the operation outliving the key material. */
static int count_cb(int devId, wc_CryptoInfo *info, void *ctx)
{
    (void)ctx;

    if (devId != expect_devid) {
        seen_wrong_devid++;
    }
    else if (info != NULL && info->algo_type >= 0 &&
             info->algo_type <= WC_ALGO_TYPE_MAX) {
        seen[info->algo_type]++;
    }
    seen_total++;

    if (info != NULL && info->algo_type == WC_ALGO_TYPE_HMAC &&
        info->hmac.hmac != NULL && info->hmac.hmac->keyRaw != NULL) {
        word16 i;
        for (i = 0; i < info->hmac.hmac->keyLen; i++) {
            key_sink = info->hmac.hmac->keyRaw[i];
        }
    }

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
    if (mute_keywrap && info != NULL &&
        info->algo_type == WC_ALGO_TYPE_CIPHER &&
        info->cipher.type == WC_CIPHER_AES_KEYWRAP) {
        /* Success, but outResSz is left at zero. */
        return 0;
    }
#endif

    return CRYPTOCB_UNAVAILABLE;
}

static void reset_counts(int devId)
{
    XMEMSET(seen, 0, sizeof(seen));
    seen_total = 0;
    seen_wrong_devid = 0;
    expect_devid = devId;
}

static int fail(const char *label, psa_status_t status)
{
    printf("FAIL %s status=%d\n", label, (int)status);
    return 1;
}

static int exercise_random(void)
{
    uint8_t out[16];
    psa_status_t st;

    st = psa_generate_random(out, sizeof(out));
    if (st != PSA_SUCCESS)
        return fail("psa_generate_random", st);
    return 0;
}

static int exercise_hash(void)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t digest[PSA_HASH_MAX_SIZE];
    size_t digest_len = 0;
    psa_status_t st;

    st = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg) - 1,
                          digest, sizeof(digest), &digest_len);
    if (st != PSA_SUCCESS)
        return fail("psa_hash_compute", st);
    return 0;
}

static int exercise_mac(psa_algorithm_t alg, psa_key_type_t type,
                        size_t key_len, const char *label)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t key_bytes[32];
    uint8_t mac[PSA_MAC_MAX_SIZE];
    size_t mac_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(key_bytes, 0x5a, sizeof(key_bytes));

    psa_set_key_type(&attr, type);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, alg);

    st = psa_import_key(&attr, key_bytes, key_len, &key);
    if (st != PSA_SUCCESS)
        return fail(label, st);

    st = psa_mac_compute(key, alg, msg, sizeof(msg) - 1,
                         mac, sizeof(mac), &mac_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail(label, st);
    return 0;
}

static int exercise_cipher(void)
{
    static const uint8_t plain[32] = { 0 };
    uint8_t key_bytes[16];
    uint8_t out[64];
    size_t out_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(key_bytes, 0x2b, sizeof(key_bytes));

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);

    st = psa_import_key(&attr, key_bytes, sizeof(key_bytes), &key);
    if (st != PSA_SUCCESS)
        return fail("aes import", st);

    st = psa_cipher_encrypt(key, PSA_ALG_CBC_NO_PADDING, plain, sizeof(plain),
                            out, sizeof(out), &out_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_cipher_encrypt", st);
    return 0;
}

static int exercise_ecdsa(void)
{
    uint8_t digest[32];
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(digest, 0x11, sizeof(digest));

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("ecc generate", st);

    st = psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                       digest, sizeof(digest), sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_hash ecdsa", st);
    return 0;
}

#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
/* PSA_ALG_DETERMINISTIC_ECDSA promises RFC 6979, and the crypto callback
 * contract carries no deterministic flag, so wolfPSA pins that algorithm to
 * local execution. Two things have to hold: the signature is reproducible,
 * and the sign never reaches the device even though one is selected. The
 * second is the real guard, because the declining callback in this test
 * leaves the software path reproducible either way.
 *
 * Called with a device selected and the counters freshly reset. */
static int check_deterministic_ecdsa_stays_local(void)
{
    uint8_t digest[32];
    uint8_t sig_a[PSA_SIGNATURE_MAX_SIZE];
    uint8_t sig_b[PSA_SIGNATURE_MAX_SIZE];
    size_t len_a = 0;
    size_t len_b = 0;
    psa_algorithm_t alg = PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256);
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    XMEMSET(digest, 0x33, sizeof(digest));

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, alg);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("deterministic ecdsa generate", st);

    /* Key generation is allowed to offload; only the signing is measured. */
    reset_counts(expect_devid);

    st = psa_sign_hash(key, alg, digest, sizeof(digest),
                       sig_a, sizeof(sig_a), &len_a);
    if (st != PSA_SUCCESS) {
        ret = fail("deterministic ecdsa sign 1", st);
    }

    if (ret == 0) {
        st = psa_sign_hash(key, alg, digest, sizeof(digest),
                           sig_b, sizeof(sig_b), &len_b);
        if (st != PSA_SUCCESS)
            ret = fail("deterministic ecdsa sign 2", st);
    }

    if (ret == 0 && (len_a != len_b ||
                     XMEMCMP(sig_a, sig_b, len_a) != 0)) {
        printf("FAIL deterministic ECDSA produced two different"
               " signatures\n");
        ret = 1;
    }

    if (ret == 0 && seen[WC_ALGO_TYPE_PK] != 0) {
        printf("FAIL deterministic ECDSA dispatched %d pk operation(s) to a"
               " device\n", seen[WC_ALGO_TYPE_PK]);
        ret = 1;
    }
    else if (ret == 0) {
        printf("deterministic ECDSA: stayed local\n");
    }

    psa_destroy_key(key);
    return ret;
}
#endif /* WOLFSSL_ECDSA_DETERMINISTIC_K */

#ifdef HAVE_ED25519
static int exercise_eddsa(void)
{
    static const uint8_t msg[] = "wolfPSA devId coverage";
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
    psa_set_key_bits(&attr, 255);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_PURE_EDDSA);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("ed25519 generate", st);

    st = psa_sign_message(key, PSA_ALG_PURE_EDDSA, msg, sizeof(msg) - 1,
                          sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_message ed25519", st);
    return 0;
}
#endif /* HAVE_ED25519 */

#ifdef HAVE_AES_KEYWRAP
/* RFC 3394 section 4.1 vector, so the software fallback after a declined
 * dispatch is checked against a known answer rather than just a status. */
static const uint8_t kKekRfc3394[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

static const uint8_t kPlainRfc3394[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

static const uint8_t kCipherRfc3394[24] = {
    0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
    0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
    0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
};

static int exercise_keywrap(void)
{
    uint8_t wrapped[32];
    size_t wrapped_len = 0;
    psa_key_attributes_t kattr = psa_key_attributes_init();
    psa_key_attributes_t tattr = psa_key_attributes_init();
    psa_key_id_t kek = PSA_KEY_ID_NULL;
    psa_key_id_t target = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_WRAP);
    psa_set_key_algorithm(&kattr, PSA_ALG_KW);

    st = psa_import_key(&kattr, kKekRfc3394, sizeof(kKekRfc3394), &kek);
    if (st != PSA_SUCCESS)
        return fail("kek import", st);

    psa_set_key_type(&tattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&tattr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&tattr, PSA_ALG_KW);

    st = psa_import_key(&tattr, kPlainRfc3394, sizeof(kPlainRfc3394), &target);
    if (st != PSA_SUCCESS) {
        psa_destroy_key(kek);
        return fail("wrap target import", st);
    }

    st = psa_wrap_key(kek, PSA_ALG_KW, target,
                      wrapped, sizeof(wrapped), &wrapped_len);
    if (st != PSA_SUCCESS) {
        ret = fail("psa_wrap_key", st);
    }
    else if (wrapped_len != sizeof(kCipherRfc3394) ||
             XMEMCMP(wrapped, kCipherRfc3394, sizeof(kCipherRfc3394)) != 0) {
        printf("FAIL psa_wrap_key produced the wrong ciphertext\n");
        ret = 1;
    }

    psa_destroy_key(target);
    psa_destroy_key(kek);
    return ret;
}
#endif /* HAVE_AES_KEYWRAP */

#ifdef HAVE_CURVE448
/* X448 keygen plus agreement, so the curve448 crypto callbacks wolfCrypt
 * gained are actually exercised rather than assumed. */
static int exercise_x448(void)
{
    uint8_t peer[56];
    uint8_t secret[56];
    size_t peer_len = 0;
    size_t secret_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&attr,
                     PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_MONTGOMERY));
    psa_set_key_bits(&attr, 448);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE |
                                   PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("x448 generate", st);

    st = psa_export_public_key(key, peer, sizeof(peer), &peer_len);
    if (st != PSA_SUCCESS) {
        ret = fail("x448 export public", st);
    }

    if (ret == 0) {
        st = psa_raw_key_agreement(PSA_ALG_ECDH, key, peer, peer_len,
                                   secret, sizeof(secret), &secret_len);
        if (st != PSA_SUCCESS)
            ret = fail("psa_raw_key_agreement x448", st);
    }

    psa_destroy_key(key);
    return ret;
}
#endif /* HAVE_CURVE448 */

#ifndef NO_RSA
static int exercise_rsa(void)
{
    uint8_t digest[32];
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    size_t sig_len = 0;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_status_t st;

    XMEMSET(digest, 0x22, sizeof(digest));

    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, 2048);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256));

    st = psa_generate_key(&attr, &key);
    if (st != PSA_SUCCESS)
        return fail("rsa generate", st);

    st = psa_sign_hash(key, PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256),
                       digest, sizeof(digest), sig, sizeof(sig), &sig_len);
    psa_destroy_key(key);
    if (st != PSA_SUCCESS)
        return fail("psa_sign_hash rsa", st);
    return 0;
}
#endif /* NO_RSA */

static int exercise_all(void)
{
    int ret = 0;

    ret |= exercise_random();
    ret |= exercise_hash();
    ret |= exercise_mac(PSA_ALG_HMAC(PSA_ALG_SHA_256), PSA_KEY_TYPE_HMAC,
                        32, "hmac");
#ifdef WOLFSSL_CMAC
    ret |= exercise_mac(PSA_ALG_CMAC, PSA_KEY_TYPE_AES, 16, "cmac");
#endif
    ret |= exercise_cipher();
#ifdef HAVE_AES_KEYWRAP
    ret |= exercise_keywrap();
#endif
    ret |= exercise_ecdsa();
#ifdef HAVE_ED25519
    ret |= exercise_eddsa();
#endif
#ifdef HAVE_CURVE448
    ret |= exercise_x448();
#endif
#ifndef NO_RSA
    ret |= exercise_rsa();
#endif

    return ret;
}

static int require_seen(int algo_type)
{
    if (seen[algo_type] == 0) {
        printf("FAIL no %s operation reached the callback\n",
               algo_name(algo_type));
        return 1;
    }
    printf("  %-6s dispatched %d time(s)\n", algo_name(algo_type),
           seen[algo_type]);
    return 0;
}

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
/* A device that answers "success" without writing an output length must not
 * be reported to the caller as a zero-length success: psa_wrap_key() would
 * leave *data_length untouched and psa_unwrap_key() would return a null key
 * handle. Exercises the guards those two paths carry. */
static int check_keywrap_silent_device(void)
{
    uint8_t wrapped[32];
    uint8_t attacked[32];
    size_t wrapped_len = 0;
    psa_key_attributes_t kattr = psa_key_attributes_init();
    psa_key_attributes_t tattr = psa_key_attributes_init();
    psa_key_id_t kek = PSA_KEY_ID_NULL;
    psa_key_id_t target = PSA_KEY_ID_NULL;
    psa_key_id_t unwrapped = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 0;

    psa_set_key_type(&kattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&kattr, PSA_KEY_USAGE_WRAP |
                                    PSA_KEY_USAGE_UNWRAP);
    psa_set_key_algorithm(&kattr, PSA_ALG_KW);

    st = psa_import_key(&kattr, kKekRfc3394, sizeof(kKekRfc3394), &kek);
    if (st != PSA_SUCCESS)
        return fail("silent device kek import", st);

    psa_set_key_type(&tattr, PSA_KEY_TYPE_AES);
    psa_set_key_usage_flags(&tattr, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&tattr, PSA_ALG_KW);

    st = psa_import_key(&tattr, kPlainRfc3394, sizeof(kPlainRfc3394),
                        &target);
    if (st != PSA_SUCCESS) {
        psa_destroy_key(kek);
        return fail("silent device target import", st);
    }

    mute_keywrap = 1;

    wrapped_len = 0xdead;
    st = psa_wrap_key(kek, PSA_ALG_KW, target, wrapped, sizeof(wrapped),
                      &wrapped_len);
    if (st == PSA_SUCCESS) {
        printf("FAIL psa_wrap_key reported success for a device that"
               " produced nothing\n");
        ret = 1;
    }

    if (ret == 0) {
        XMEMCPY(attacked, kCipherRfc3394, sizeof(kCipherRfc3394));
        st = psa_unwrap_key(&tattr, kek, PSA_ALG_KW, attacked,
                            sizeof(kCipherRfc3394), &unwrapped);
        if (st == PSA_SUCCESS) {
            printf("FAIL psa_unwrap_key reported success for a device that"
                   " produced nothing\n");
            ret = 1;
        }
        else if (unwrapped != PSA_KEY_ID_NULL) {
            printf("FAIL psa_unwrap_key failed but handed back a key id\n");
            ret = 1;
        }
    }

    mute_keywrap = 0;

    if (ret == 0) {
        printf("silent device: wrap and unwrap both refused\n");
    }

    psa_destroy_key(target);
    psa_destroy_key(kek);
    return ret;
}
#endif /* !NO_AES && HAVE_AES_KEYWRAP */

static int check_families(void)
{
    int ret = 0;

    ret |= require_seen(WC_ALGO_TYPE_HASH);
    ret |= require_seen(WC_ALGO_TYPE_CIPHER);
    ret |= require_seen(WC_ALGO_TYPE_PK);
    ret |= require_seen(WC_ALGO_TYPE_HMAC);
#ifdef WOLFSSL_CMAC
    ret |= require_seen(WC_ALGO_TYPE_CMAC);
#endif
    if (seen[WC_ALGO_TYPE_RNG] == 0 && seen[WC_ALGO_TYPE_SEED] == 0) {
        printf("FAIL no rng operation reached the callback\n");
        ret = 1;
    }
    if (seen_wrong_devid != 0) {
        printf("FAIL %d operation(s) carried a devId other than %d\n",
               seen_wrong_devid, expect_devid);
        ret = 1;
    }
    return ret;
}

int main(void)
{
    int ret = 0;
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS)
        return fail("psa_crypto_init", st);

    /* Phase 1: no device registered and no explicit devId, so every wolfCrypt
     * object must be built with INVALID_DEVID. */
    if (wolfPSA_GetDefaultDevID() != INVALID_DEVID) {
        printf("FAIL default devId is not INVALID_DEVID with no device"
               " registered\n");
        return 1;
    }

    /* Phase 2: a registered device and still no explicit devId. wolfCrypt's
     * own selection picks the only registered device, so every family must
     * reach it. An algorithm that never ran its wc_*Init() carries devId 0
     * instead and goes missing here. */
    if (wc_CryptoCb_RegisterDevice(PROBE_DEVID, count_cb, NULL) != 0) {
        printf("FAIL wc_CryptoCb_RegisterDevice(probe)\n");
        return 1;
    }

    if (wolfPSA_GetDefaultDevID() != PROBE_DEVID) {
        printf("FAIL default devId did not follow wolfCrypt device selection"
               " (got %d, want %d)\n", wolfPSA_GetDefaultDevID(),
               PROBE_DEVID);
        ret = 1;
    }

    if (ret == 0) {
        printf("wolfCrypt device selection (devId %d):\n", PROBE_DEVID);
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

    /* Phase 3: an explicit devId must win over that selection. The probe
     * device stays registered, so a stale read shows up as a dispatch on
     * PROBE_DEVID rather than TEST_DEVID. */
    if (ret == 0 && wc_CryptoCb_RegisterDevice(TEST_DEVID, count_cb,
                                               NULL) != 0) {
        printf("FAIL wc_CryptoCb_RegisterDevice(test)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_SetDefaultDevID(TEST_DEVID) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != TEST_DEVID) {
        printf("FAIL explicit devId did not override device selection\n");
        ret = 1;
    }

    if (ret == 0) {
        printf("explicit devId %d:\n", TEST_DEVID);
        reset_counts(TEST_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

#ifdef WOLFSSL_ECDSA_DETERMINISTIC_K
    if (ret == 0) {
        ret = check_deterministic_ecdsa_stays_local();
    }
    reset_counts(TEST_DEVID);
#endif

#if !defined(NO_AES) && defined(HAVE_AES_KEYWRAP)
    if (ret == 0) {
        ret = check_keywrap_silent_device();
    }
    reset_counts(TEST_DEVID);
#endif

    /* Phase 4: an explicit INVALID_DEVID is the opt-out, so nothing may
     * dispatch even though both devices are still registered. */
    if (ret == 0 && wolfPSA_SetDefaultDevID(INVALID_DEVID) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID(INVALID_DEVID)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != INVALID_DEVID) {
        printf("FAIL INVALID_DEVID did not force local execution\n");
        ret = 1;
    }

    if (ret == 0) {
        reset_counts(INVALID_DEVID);
        ret = exercise_all();
    }

    if (ret == 0 && seen_total != 0) {
        printf("FAIL %d operation(s) dispatched after opting out\n",
               seen_total);
        ret = 1;
    }
    else if (ret == 0) {
        printf("opt-out: no dispatches\n");
    }

    /* Phase 5: WOLFPSA_DEVID_DEFAULT hands the choice back to wolfCrypt, so
     * the opt-out and any explicit devId are both reversible. TEST_DEVID is
     * unregistered first, leaving the probe as wolfCrypt's own selection. */
    wc_CryptoCb_UnRegisterDevice(TEST_DEVID);

    if (ret == 0 && wolfPSA_SetDefaultDevID(WOLFPSA_DEVID_DEFAULT) != 0) {
        printf("FAIL wolfPSA_SetDefaultDevID(WOLFPSA_DEVID_DEFAULT)\n");
        ret = 1;
    }

    if (ret == 0 && wolfPSA_GetDefaultDevID() != PROBE_DEVID) {
        printf("FAIL default was not handed back to wolfCrypt (got %d,"
               " want %d)\n", wolfPSA_GetDefaultDevID(), PROBE_DEVID);
        ret = 1;
    }

    if (ret == 0) {
        printf("handed back to wolfCrypt (devId %d):\n", PROBE_DEVID);
        reset_counts(PROBE_DEVID);
        ret = exercise_all();
    }

    if (ret == 0) {
        ret = check_families();
    }

    wc_CryptoCb_UnRegisterDevice(PROBE_DEVID);

    if (ret != 0)
        return 1;

    printf("PSA devId crypto callback test: OK\n");
    return 0;
}
