/* psa_store_dir_validation_test.c
 *
 * Regression test: the POSIX store accepted any pre-existing directory as
 * its store location. The directory check only required the path to be a
 * directory, so a directory owned by another user, or writable by group or
 * other, was used as-is. A local peer with write access to such a directory
 * can rename record files out from under the store and replace a stored key
 * with an attacker-chosen one. The store now requires a directory owned by
 * the effective user with no group or other write bits, and fails closed
 * with a storage error otherwise.
 *
 * The ownership branch is not exercised here: a non-root test user cannot
 * create a directory owned by someone else. The mode branch carries the
 * gate.
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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <psa/crypto.h>

static int test_dir(const char *label, mode_t mode, psa_status_t expected)
{
    char dir[] = "/tmp/wolfpsa_store_dir_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    if (mkdtemp(dir) == NULL) {
        printf("FAIL %s: mkdtemp failed\n", label);
        return 1;
    }
    if (chmod(dir, mode) != 0) {
        printf("FAIL %s: chmod failed\n", label);
        (void)rmdir(dir);
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("FAIL %s: setenv failed\n", label);
        (void)rmdir(dir);
        return 1;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_PERSISTENCE_DEFAULT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != expected) {
        printf("FAIL %s: import status=%d expected=%d\n", label,
               (int)st, (int)expected);
        goto out;
    }
    if (expected != PSA_SUCCESS) {
        ok = 1;
        goto out;
    }
    (void)psa_destroy_key(key_id);
    ok = 1;

out:
    (void)rmdir(dir);
    return ok ? 0 : 1;
}

int main(void)
{
    int ret = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_store_dir_validation_test: psa_crypto_init failed\n");
        return 1;
    }

    /* mkdtemp creates 0700: the private-directory baseline must work. */
    ret |= test_dir("dir-0700", 0700, PSA_SUCCESS);
    /* Group-writable: a local peer can rename records out from under the
     * store. */
    ret |= test_dir("dir-0775", 0775, PSA_ERROR_STORAGE_FAILURE);
    /* Other-writable: same. */
    ret |= test_dir("dir-0707", 0707, PSA_ERROR_STORAGE_FAILURE);
    /* Readable by others but not writable: still private enough. */
    ret |= test_dir("dir-0755", 0755, PSA_SUCCESS);

    if (ret != 0) {
        printf("PSA store dir validation test: FAIL\n");
        return 1;
    }

    printf("PSA store dir validation test: OK\n");
    return 0;
}
