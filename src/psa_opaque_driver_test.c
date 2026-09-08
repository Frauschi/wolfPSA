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

/**
 * A software stand-in for a hardware key store, so the generic opaque-driver
 * paths can be exercised without the hardware any real driver needs. Built
 * only when WOLFPSA_TEST_OPAQUE_DRIVER is defined; never in a shipped library.
 *
 * The key material stays in a table here and what wolfPSA stores is a 16-byte
 * reference into it - the same length as an AES-128 key on purpose, so a path
 * that told the two apart by length would fail the tests rather than pass them.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_PSA_ENGINE) && defined(WOLFPSA_TEST_OPAQUE_DRIVER)

#include "psa_opaque_driver_test.h"

#include <wolfpsa/psa_engine.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hmac.h>
#ifdef WOLFSSL_CMAC
    #include <wolfssl/wolfcrypt/cmac.h>
#endif

#define TEST_DRV_SLOTS      8
#define TEST_DRV_MAX_KEY    64
#define TEST_DRV_REF_SZ     16
#define TEST_DRV_MAGIC_0    0x54 /* 'T' */
#define TEST_DRV_MAGIC_1    0x44 /* 'D' */

/* The reference, then for an ECC key its public point. */
#define TEST_DRV_KEY_DATA_SZ (TEST_DRV_REF_SZ + 1 + (2 * 32))

typedef struct test_drv_slot {
    int used;
    psa_key_type_t type;
    size_t bits;
    uint8_t key[TEST_DRV_MAX_KEY];
    size_t key_length;
} test_drv_slot;

static test_drv_slot test_drv_slots[TEST_DRV_SLOTS];

unsigned long wolfpsa_test_driver_hits;

static psa_status_t test_drv_make_ref(int slot, uint8_t* out, size_t out_size)
{
    if (out_size < TEST_DRV_REF_SZ) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    XMEMSET(out, 0, TEST_DRV_REF_SZ);
    out[0] = TEST_DRV_MAGIC_0;
    out[1] = TEST_DRV_MAGIC_1;
    out[2] = (uint8_t)slot;
    return PSA_SUCCESS;
}

static int test_drv_parse_ref(const uint8_t* data, size_t data_length)
{
    if (data == NULL || data_length < TEST_DRV_REF_SZ ||
        data[0] != TEST_DRV_MAGIC_0 || data[1] != TEST_DRV_MAGIC_1 ||
        data[2] >= TEST_DRV_SLOTS) {
        return -1;
    }

    return (int)data[2];
}

static int test_drv_take_slot(void)
{
    int i;

    for (i = 0; i < TEST_DRV_SLOTS; i++) {
        if (!test_drv_slots[i].used) {
            XMEMSET(&test_drv_slots[i], 0, sizeof(test_drv_slots[i]));
            test_drv_slots[i].used = 1;
            return i;
        }
    }

    return -1;
}

/* Whether the key material a slot holds still matches what the driver was told
 * it would be, which is all a stand-in can check. */
static psa_status_t test_drv_load(const uint8_t* key_data,
                                  size_t key_data_length,
                                  test_drv_slot** slot)
{
    int idx = test_drv_parse_ref(key_data, key_data_length);

    if (idx < 0 || !test_drv_slots[idx].used) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *slot = &test_drv_slots[idx];
    return PSA_SUCCESS;
}

void wolfpsa_test_driver_reset(void)
{
    XMEMSET(test_drv_slots, 0, sizeof(test_drv_slots));
    wolfpsa_test_driver_hits = 0;
}

size_t wolfpsa_test_driver_slots_used(void)
{
    size_t used = 0;
    int i;

    for (i = 0; i < TEST_DRV_SLOTS; i++) {
        if (test_drv_slots[i].used) {
            used++;
        }
    }

    return used;
}

psa_status_t wolfpsa_test_driver_inject(const psa_key_attributes_t* attributes,
                                        const uint8_t* key, size_t key_length,
                                        uint8_t* key_data,
                                        size_t key_data_size,
                                        size_t* key_data_length)
{
    int idx;
    psa_status_t status;

    if (key_length > TEST_DRV_MAX_KEY) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    idx = test_drv_take_slot();
    if (idx < 0) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    status = test_drv_make_ref(idx, key_data, key_data_size);
    if (status != PSA_SUCCESS) {
        test_drv_slots[idx].used = 0;
        return status;
    }

    test_drv_slots[idx].type = psa_get_key_type(attributes);
    test_drv_slots[idx].bits = psa_get_key_bits(attributes);
    XMEMCPY(test_drv_slots[idx].key, key, key_length);
    test_drv_slots[idx].key_length = key_length;
    *key_data_length = TEST_DRV_REF_SZ;
    return PSA_SUCCESS;
}

static psa_status_t test_drv_validate(const psa_key_attributes_t* attributes,
                                      const uint8_t* data, size_t data_length)
{
    psa_key_type_t type = psa_get_key_type(attributes);

    if (!PSA_KEY_LIFETIME_IS_VOLATILE(psa_get_key_lifetime(attributes))) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (type != PSA_KEY_TYPE_AES && type != PSA_KEY_TYPE_DERIVE &&
        type != PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (data != NULL && test_drv_parse_ref(data, data_length) < 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t test_drv_generate(const psa_key_attributes_t* attributes,
                                      uint8_t* key_data, size_t key_data_size,
                                      size_t* key_data_length)
{
    ecc_key ecc;
    WC_RNG rng;
    word32 pub_len = 1 + (2 * 32);
    int idx;
    int ret;
    psa_status_t status;

    if (psa_get_key_type(attributes) !=
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    if (key_data_size < TEST_DRV_KEY_DATA_SZ) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    idx = test_drv_take_slot();
    if (idx < 0) {
        return PSA_ERROR_INSUFFICIENT_STORAGE;
    }

    ret = wc_InitRng(&rng);
    if (ret == 0) {
        ret = wc_ecc_init(&ecc);
        if (ret != 0) {
            wc_FreeRng(&rng);
        }
    }
    if (ret != 0) {
        test_drv_slots[idx].used = 0;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    ret = wc_ecc_make_key_ex(&rng, 32, &ecc, ECC_SECP256R1);
    if (ret == 0) {
        word32 priv_len = 32;

        ret = wc_ecc_export_private_only(&ecc, test_drv_slots[idx].key,
                                         &priv_len);
        if (ret == 0) {
            test_drv_slots[idx].key_length = priv_len;
            ret = wc_ecc_export_x963_ex(&ecc, key_data + TEST_DRV_REF_SZ,
                                        &pub_len, 0);
        }
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&ecc);

    if (ret != 0) {
        test_drv_slots[idx].used = 0;
        return PSA_ERROR_HARDWARE_FAILURE;
    }

    status = test_drv_make_ref(idx, key_data, key_data_size);
    if (status != PSA_SUCCESS) {
        test_drv_slots[idx].used = 0;
        return status;
    }

    test_drv_slots[idx].type = psa_get_key_type(attributes);
    test_drv_slots[idx].bits = psa_get_key_bits(attributes);
    *key_data_length = TEST_DRV_REF_SZ + pub_len;
    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}

static psa_status_t test_drv_destroy(const psa_key_attributes_t* attributes,
                                     const uint8_t* key_data,
                                     size_t key_data_length)
{
    test_drv_slot* slot;
    psa_status_t status;

    (void)attributes;

    status = test_drv_load(key_data, key_data_length, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }

    XMEMSET(slot, 0, sizeof(*slot));
    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}

static psa_status_t test_drv_export_public(
    const psa_key_attributes_t* attributes, const uint8_t* key_data,
    size_t key_data_length, uint8_t* data, size_t data_size,
    size_t* data_length)
{
    size_t point_len;

    (void)attributes;

    if (key_data_length <= TEST_DRV_REF_SZ) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    point_len = key_data_length - TEST_DRV_REF_SZ;
    if (data_size < point_len) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    XMEMCPY(data, key_data + TEST_DRV_REF_SZ, point_len);
    *data_length = point_len;
    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}

static psa_status_t test_drv_ecc_bind(const uint8_t* key_data,
                                      size_t key_data_length, int curve_id,
                                      psa_algorithm_t alg, ecc_key* key)
{
    test_drv_slot* slot;
    psa_status_t status;
    int ret;

    (void)alg;

    if (curve_id != ECC_SECP256R1) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = test_drv_load(key_data, key_data_length, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ret = wc_ecc_init(key);
    if (ret == 0) {
        ret = wc_ecc_import_private_key_ex(slot->key,
                                           (word32)slot->key_length, NULL, 0,
                                           key, curve_id);
        if (ret != 0) {
            wc_ecc_free(key);
        }
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}

#ifndef NO_AES
static psa_status_t test_drv_aes_bind(const uint8_t* key_data,
                                      size_t key_data_length,
                                      psa_algorithm_t alg, Aes* aes)
{
    test_drv_slot* slot;
    psa_status_t status;
    int ret;

    (void)alg;

    status = test_drv_load(key_data, key_data_length, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }
    if (slot->type != PSA_KEY_TYPE_AES) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = wc_AesInit(aes, NULL, INVALID_DEVID);
    if (ret == 0) {
        /* No IV: the caller sets one, exactly as a real bind leaves it. */
        ret = wc_AesSetKey(aes, slot->key, (word32)slot->key_length, NULL,
                           AES_ENCRYPTION);
        if (ret != 0) {
            wc_AesFree(aes);
        }
    }
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}
#endif /* NO_AES */

#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
static psa_status_t test_drv_cmac_bind(const uint8_t* key_data,
                                       size_t key_data_length,
                                       psa_algorithm_t alg, Cmac* cmac)
{
    test_drv_slot* slot;
    psa_status_t status;
    int ret;

    if (alg != PSA_ALG_CMAC) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = test_drv_load(key_data, key_data_length, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ret = wc_InitCmac_ex(cmac, slot->key, (word32)slot->key_length,
                         WC_CMAC_AES, NULL, NULL, INVALID_DEVID);
    if (ret != 0) {
        return wc_error_to_psa_status(ret);
    }

    wolfpsa_test_driver_hits++;
    return PSA_SUCCESS;
}
#endif /* WOLFSSL_CMAC && !NO_AES */

/* Generate, destroy, export_public and the binds are filled in; the ops a
 * device that keeps its keys cannot offer are left NULL on purpose, so the
 * tests see the generic PSA_ERROR_NOT_SUPPORTED an omission produces. */
const wolfpsa_opaque_driver wolfpsa_opaque_driver_test = {
    PSA_KEY_LOCATION_WOLFPSA_TEST,
    PSA_KEY_LOCATION_LOCAL_STORAGE, /* no alias */
    TEST_DRV_KEY_DATA_SZ,
    test_drv_validate,
    test_drv_generate,
    test_drv_destroy,
    test_drv_export_public,
    NULL,                           /* export_private */
    NULL,                           /* copy */
    NULL,                           /* key_agreement */
    NULL,                           /* wrap */
    NULL,                           /* unwrap */
    NULL                            /* derive */
#ifdef HAVE_ECC
    , test_drv_ecc_bind
#endif
#ifndef NO_AES
    , test_drv_aes_bind
#endif
#if defined(WOLFSSL_CMAC) && !defined(NO_AES)
    , test_drv_cmac_bind
#endif
};

#endif /* WOLFSSL_PSA_ENGINE && WOLFPSA_TEST_OPAQUE_DRIVER */
