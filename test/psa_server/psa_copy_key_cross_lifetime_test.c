/*
 * psa_copy_key_cross_lifetime_test.c
 *
 * Regression test for Fenrir finding #13859: psa_copy_key() rejected any
 * copy whose destination lifetime differed from the source lifetime, in
 * both the volatile and the persistent source paths. The PSA Crypto API
 * defines psa_copy_key() as supporting a destination with a different
 * lifetime, and a copy between local volatile and persistent storage does
 * not cross a security boundary, so such copies must succeed.
 *
 * The test covers both cross-lifetime directions (volatile to persistent
 * and persistent to volatile) and the two same-lifetime directions, which
 * must keep working. The destination key is checked to carry the
 * destination lifetime.
 *
 * This file is part of wolfPSA.
 *
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is licensed under the 3-clause BSD license. See the file
 * LICENSE or wolfSSL.md in the distribution root for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#include <wolfpsa/psa/crypto.h>

/* Remove the key store directory and anything left in it. */
static void cleanup_store(const char *dir)
{
    DIR *d;
    struct dirent *ent;

    d = opendir(dir);
    if (d == NULL) {
        return;
    }
    while ((ent = readdir(d)) != NULL) {
        char path[4096];

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        (void)unlink(path);
    }
    closedir(d);
    (void)rmdir(dir);
}

/* Fill in the attributes of a key with the given policy. */
static void set_key_attrs(psa_key_attributes_t *attrs,
                          psa_key_lifetime_t lifetime, psa_key_id_t key_id)
{
    psa_set_key_type(attrs, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(attrs, 256);
    psa_set_key_usage_flags(attrs, PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(attrs, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_lifetime(attrs, lifetime);
    if (lifetime == PSA_KEY_LIFETIME_PERSISTENT) {
        psa_set_key_id(attrs, key_id);
    }
}

/* Create a key with the given lifetime. */
static psa_status_t make_key(psa_key_lifetime_t lifetime, psa_key_id_t key_id,
                             psa_key_id_t *key)
{
    static const uint8_t hmac_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_status_t status;

    set_key_attrs(&attrs, lifetime, key_id);
    *key = PSA_KEY_ID_NULL;
    status = psa_import_key(&attrs, hmac_key, sizeof(hmac_key), key);
    return status;
}

/* Copy a key from the source lifetime to the destination lifetime and
 * check the result and the stored lifetime of the destination key. */
static int run_cross_lifetime_case(psa_key_lifetime_t src_lifetime,
                                   psa_key_lifetime_t dst_lifetime,
                                   psa_key_id_t src_id, psa_key_id_t dst_id,
                                   const char *label)
{
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t check = psa_key_attributes_init();
    psa_key_id_t src_key = PSA_KEY_ID_NULL;
    psa_key_id_t dst_key = PSA_KEY_ID_NULL;
    psa_status_t status;
    int ok = 0;

    status = make_key(src_lifetime, src_id, &src_key);
    if (status != PSA_SUCCESS) {
        printf("FAIL %s: source key create: 0x%08x\n", label,
               (unsigned int)status);
        return 1;
    }
    set_key_attrs(&attrs, dst_lifetime, dst_id);
    status = psa_copy_key(src_key, &attrs, &dst_key);
    if (status != PSA_SUCCESS) {
        printf("FAIL %s: psa_copy_key: 0x%08x (expected success)\n", label,
               (unsigned int)status);
        ok = 1;
    } else if (psa_get_key_attributes(dst_key, &check) != PSA_SUCCESS) {
        printf("FAIL %s: psa_get_key_attributes: 0x%08x\n", label,
               (unsigned int)status);
        ok = 1;
    } else if (psa_get_key_lifetime(&check) != dst_lifetime) {
        printf("FAIL %s: dst lifetime 0x%08x, expected 0x%08x\n", label,
               (unsigned int)psa_get_key_lifetime(&check),
               (unsigned int)dst_lifetime);
        ok = 1;
    } else {
        printf("PASS %s\n", label);
    }

    if (dst_key != PSA_KEY_ID_NULL) {
        (void)psa_destroy_key(dst_key);
    }
    (void)psa_destroy_key(src_key);
    return ok;
}

int main(void)
{
    char store_dir[] = "/tmp/wolfpsa_copy_cross_lifetime_XXXXXX";
    int ret = 0;

    if (mkdtemp(store_dir) == NULL) {
        printf("psa_copy_key_cross_lifetime_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("psa_copy_key_cross_lifetime_test: setenv failed\n");
        ret = 1;
    } else if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_copy_key_cross_lifetime_test: psa_crypto_init failed\n");
        ret = 1;
    } else {
        /* Cross-lifetime copies: the fix under test. */
        ret |= run_cross_lifetime_case(
            PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LIFETIME_PERSISTENT,
            PSA_KEY_ID_NULL, PSA_KEY_ID_USER_MIN + 201,
            "volatile -> persistent");
        ret |= run_cross_lifetime_case(
            PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LIFETIME_VOLATILE,
            PSA_KEY_ID_USER_MIN + 202, PSA_KEY_ID_NULL,
            "persistent -> volatile");
        /* Same-lifetime copies: must keep working. */
        ret |= run_cross_lifetime_case(
            PSA_KEY_LIFETIME_VOLATILE, PSA_KEY_LIFETIME_VOLATILE,
            PSA_KEY_ID_NULL, PSA_KEY_ID_NULL,
            "volatile -> volatile");
        ret |= run_cross_lifetime_case(
            PSA_KEY_LIFETIME_PERSISTENT, PSA_KEY_LIFETIME_PERSISTENT,
            PSA_KEY_ID_USER_MIN + 203, PSA_KEY_ID_USER_MIN + 204,
            "persistent -> persistent");
        if (ret == 0) {
            printf("psa_copy_key_cross_lifetime_test: all tests passed\n");
        }
    }
    cleanup_store(store_dir);
    return ret;
}
