/* psa_opaque_driver_test.c
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
 * The opaque-driver paths, against the software stand-in driver: what reaches
 * the driver, what a missing op reports, and above all that no path treats a
 * key reference as key material. The reference is 16 bytes, the length of an
 * AES-128 key, so a path that dispatched on length would fail here.
 */

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <wolfpsa/psa/crypto.h>
#include <wolfpsa/psa_locations.h>

/* Declared rather than included: psa_opaque_driver_test.h pulls in the
 * internal driver header, whose vtable this test has no business seeing. */
extern unsigned long wolfpsa_test_driver_hits;
void wolfpsa_test_driver_reset(void);
size_t wolfpsa_test_driver_slots_used(void);
psa_status_t wolfpsa_test_driver_inject(const psa_key_attributes_t *attributes,
                                        const uint8_t *key, size_t key_length,
                                        uint8_t *key_data,
                                        size_t key_data_size,
                                        size_t *key_data_length);

#define DRIVER_LIFETIME \
    PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION( \
        PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LOCATION_WOLFPSA_TEST)

static int failures;
static int checks;

static void check(int ok, const char *what)
{
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL: %s\n", what);
    }
}

static void check_status(psa_status_t got, psa_status_t want, const char *what)
{
    checks++;
    if (got != want) {
        failures++;
        printf("FAIL: %s (got %d, wanted %d)\n", what, (int)got, (int)want);
    }
}

/* A generated ECC key signs through the driver and verifies against the public
 * key the driver kept, with the private part never leaving it. */
static void test_ecc_sign_verify(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t hash[32];
    uint8_t sig[PSA_SIGNATURE_MAX_SIZE];
    uint8_t pub[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    size_t sig_len = 0;
    size_t pub_len = 0;
    unsigned long hits;

    memset(hash, 0xA5, sizeof(hash));

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_lifetime(&attr, DRIVER_LIFETIME);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                                   PSA_KEY_USAGE_VERIFY_HASH |
                                   PSA_KEY_USAGE_EXPORT);

    hits = wolfpsa_test_driver_hits;
    check_status(psa_generate_key(&attr, &key), PSA_SUCCESS,
                 "generate at the driver location");
    check(wolfpsa_test_driver_hits > hits, "generate reached the driver");
    check(wolfpsa_test_driver_slots_used() == 1, "one slot in use");

    check_status(psa_export_public_key(key, pub, sizeof(pub), &pub_len),
                 PSA_SUCCESS, "export the public key");
    check(pub_len == 65, "public key is an uncompressed P-256 point");

    check_status(psa_sign_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                               sizeof(hash), sig, sizeof(sig), &sig_len),
                 PSA_SUCCESS, "sign with the driver key");

    check_status(psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                                 sizeof(hash), sig, sig_len),
                 PSA_SUCCESS, "verify against the driver's public key");

    sig[0] ^= 0xFF;
    check_status(psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                                 sizeof(hash), sig, sig_len),
                 PSA_ERROR_INVALID_SIGNATURE, "a tampered signature fails");

    check_status(psa_destroy_key(key), PSA_SUCCESS, "destroy the driver key");
    check(wolfpsa_test_driver_slots_used() == 0, "the slot was released");
}

/* An AES key the driver holds encrypts through the bind op, and agrees with
 * the same key used locally - the reference is not what got encrypted with. */
static void test_aes_cipher(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t local = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_key_id_t plain_key = PSA_KEY_ID_NULL;
    uint8_t aes_key[16];
    uint8_t ref[64];
    size_t ref_len = 0;
    uint8_t iv[16];
    uint8_t input[16];
    uint8_t driver_out[64];
    uint8_t local_out[64];
    size_t driver_len = 0;
    size_t local_len = 0;
    unsigned long hits;

    memset(aes_key, 0x2B, sizeof(aes_key));
    memset(iv, 0x11, sizeof(iv));
    memset(input, 0x42, sizeof(input));

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_lifetime(&attr, DRIVER_LIFETIME);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);

    check_status(wolfpsa_test_driver_inject(&attr, aes_key, sizeof(aes_key),
                                            ref, sizeof(ref), &ref_len),
                 PSA_SUCCESS, "provision an AES key into the driver");
    check(ref_len == 16, "the reference is AES-128 sized, deliberately");

    check_status(psa_import_key(&attr, ref, ref_len, &key), PSA_SUCCESS,
                 "adopt the driver's AES key");

    hits = wolfpsa_test_driver_hits;
    {
        psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
        size_t part = 0;

        check_status(psa_cipher_encrypt_setup(&op, key,
                                              PSA_ALG_CBC_NO_PADDING),
                     PSA_SUCCESS, "cipher setup with a driver key");
        check_status(psa_cipher_set_iv(&op, iv, sizeof(iv)), PSA_SUCCESS,
                     "set the IV");
        check_status(psa_cipher_update(&op, input, sizeof(input), driver_out,
                                       sizeof(driver_out), &part),
                     PSA_SUCCESS, "encrypt through the driver");
        driver_len = part;
        check_status(psa_cipher_finish(&op, driver_out + driver_len,
                                       sizeof(driver_out) - driver_len, &part),
                     PSA_SUCCESS, "finish");
        driver_len += part;
    }
    check(wolfpsa_test_driver_hits > hits, "the cipher reached the driver");

    /* The same key, held locally, must produce the same ciphertext. */
    psa_set_key_type(&local, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&local, 128);
    psa_set_key_algorithm(&local, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&local, PSA_KEY_USAGE_ENCRYPT);
    check_status(psa_import_key(&local, aes_key, sizeof(aes_key), &plain_key),
                 PSA_SUCCESS, "import the same key locally");
    {
        psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
        size_t part = 0;

        check_status(psa_cipher_encrypt_setup(&op, plain_key,
                                              PSA_ALG_CBC_NO_PADDING),
                     PSA_SUCCESS, "local cipher setup");
        check_status(psa_cipher_set_iv(&op, iv, sizeof(iv)), PSA_SUCCESS,
                     "local set IV");
        check_status(psa_cipher_update(&op, input, sizeof(input), local_out,
                                       sizeof(local_out), &part),
                     PSA_SUCCESS, "local encrypt");
        local_len = part;
        check_status(psa_cipher_finish(&op, local_out + local_len,
                                       sizeof(local_out) - local_len, &part),
                     PSA_SUCCESS, "local finish");
        local_len += part;
    }

    check(driver_len == local_len && driver_len > 0 &&
          memcmp(driver_out, local_out, driver_len) == 0,
          "the driver encrypted with the key, not with its reference");

    check_status(psa_destroy_key(key), PSA_SUCCESS, "destroy the driver key");
    check_status(psa_destroy_key(plain_key), PSA_SUCCESS,
                 "destroy the local key");
}

/* A CMAC over a driver key goes through cmac_bind and matches the same key
 * used locally. */
static void test_cmac(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t local = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_key_id_t plain_key = PSA_KEY_ID_NULL;
    uint8_t aes_key[16];
    uint8_t ref[64];
    size_t ref_len = 0;
    uint8_t msg[24];
    uint8_t driver_mac[16];
    uint8_t local_mac[16];
    size_t driver_len = 0;
    size_t local_len = 0;

    memset(aes_key, 0x7C, sizeof(aes_key));
    memset(msg, 0x5A, sizeof(msg));

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_lifetime(&attr, DRIVER_LIFETIME);
    psa_set_key_algorithm(&attr, PSA_ALG_CMAC);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);

    check_status(wolfpsa_test_driver_inject(&attr, aes_key, sizeof(aes_key),
                                            ref, sizeof(ref), &ref_len),
                 PSA_SUCCESS, "provision a CMAC key into the driver");
    check_status(psa_import_key(&attr, ref, ref_len, &key), PSA_SUCCESS,
                 "adopt the driver's CMAC key");

    check_status(psa_mac_compute(key, PSA_ALG_CMAC, msg, sizeof(msg),
                                 driver_mac, sizeof(driver_mac), &driver_len),
                 PSA_SUCCESS, "CMAC through the driver");

    psa_set_key_type(&local, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&local, 128);
    psa_set_key_algorithm(&local, PSA_ALG_CMAC);
    psa_set_key_usage_flags(&local, PSA_KEY_USAGE_SIGN_MESSAGE);
    check_status(psa_import_key(&local, aes_key, sizeof(aes_key), &plain_key),
                 PSA_SUCCESS, "import the same key locally");
    check_status(psa_mac_compute(plain_key, PSA_ALG_CMAC, msg, sizeof(msg),
                                 local_mac, sizeof(local_mac), &local_len),
                 PSA_SUCCESS, "local CMAC");

    check(driver_len == local_len && driver_len > 0 &&
          memcmp(driver_mac, local_mac, driver_len) == 0,
          "the driver MACed with the key, not with its reference");

    check_status(psa_destroy_key(key), PSA_SUCCESS, "destroy the driver key");
    check_status(psa_destroy_key(plain_key), PSA_SUCCESS,
                 "destroy the local key");
}

/* Every op this driver leaves NULL reports NOT_SUPPORTED from the generic
 * code, and nothing hands back the reference in place of the key. */
static void test_declined_ops(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_attributes_t copy_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_key_id_t copy = PSA_KEY_ID_NULL;
    psa_key_id_t derived = PSA_KEY_ID_NULL;
    uint8_t out[128];
    size_t out_len = 0;

    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_lifetime(&attr, DRIVER_LIFETIME);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_HASH |
                                   PSA_KEY_USAGE_EXPORT |
                                   PSA_KEY_USAGE_COPY |
                                   PSA_KEY_USAGE_DERIVE);
    check_status(psa_generate_key(&attr, &key), PSA_SUCCESS,
                 "generate for the declined-op checks");

    /* export_private is NULL: the reference must not come back as the key. */
    out_len = 0;
    memset(out, 0, sizeof(out));
    check_status(psa_export_key(key, out, sizeof(out), &out_len),
                 PSA_ERROR_NOT_SUPPORTED, "private export is declined");
    check(out_len == 0, "nothing was written on the declined export");

    copy_attr = attr;
    check_status(psa_copy_key(key, &copy_attr, &copy),
                 PSA_ERROR_NOT_SUPPORTED, "copy is declined");

    {
        psa_key_derivation_operation_t op =
            PSA_KEY_DERIVATION_OPERATION_INIT;
        psa_key_attributes_t out_attr = PSA_KEY_ATTRIBUTES_INIT;

        psa_set_key_type(&out_attr, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&out_attr, 128);
        psa_set_key_lifetime(&out_attr, DRIVER_LIFETIME);
        psa_set_key_algorithm(&out_attr, PSA_ALG_CBC_NO_PADDING);
        psa_set_key_usage_flags(&out_attr, PSA_KEY_USAGE_ENCRYPT);

        check_status(psa_key_derivation_setup(&op,
                                              PSA_ALG_HKDF(PSA_ALG_SHA_256)),
                     PSA_SUCCESS, "set up a derivation");
        /* Refused before any derivation runs: the target is at a location
         * whose driver has no derive op. */
        check_status(psa_key_derivation_output_key(&out_attr, &op, &derived),
                     PSA_ERROR_NOT_SUPPORTED,
                     "deriving into the driver is declined");
        psa_key_derivation_abort(&op);
    }

    check_status(psa_destroy_key(key), PSA_SUCCESS, "destroy the driver key");
}

/* A location no driver answers to is a run-time status, not a build error. */
static void test_unknown_location(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    uint8_t material[16];

    memset(material, 0x33, sizeof(material));

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_lifetime(&attr,
        PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
            PSA_KEY_LIFETIME_VOLATILE,
            (psa_key_location_t)(PSA_KEY_LOCATION_VENDOR_FLAG | 0x00ABCD)));
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);

    check_status(psa_import_key(&attr, material, sizeof(material), &key),
                 PSA_ERROR_NOT_SUPPORTED,
                 "an unclaimed location is refused at run time");
}

int main(void)
{
    psa_status_t status = psa_crypto_init();

    if (status != PSA_SUCCESS) {
        printf("psa_crypto_init failed: %d\n", (int)status);
        return 1;
    }

    wolfpsa_test_driver_reset();

    test_ecc_sign_verify();
    test_aes_cipher();
    test_cmac();
    test_declined_ops();
    test_unknown_location();

    if (failures != 0) {
        printf("Opaque driver test: FAILED (%d of %d checks)\n", failures,
               checks);
        return 1;
    }

    printf("Opaque driver test: OK (passed=%d)\n", checks);
    return 0;
}
