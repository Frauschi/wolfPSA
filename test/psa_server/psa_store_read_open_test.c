/* psa_store_read_open_test.c
 *
 * Regression test: the POSIX store mapped every failed read-open to
 * WOLFPSA_STORE_NOT_AVAILABLE ("key not available") regardless of errno.
 * An existing record that cannot be opened (permissions, I/O failure)
 * therefore surfaced as PSA_ERROR_INVALID_HANDLE instead of
 * PSA_ERROR_STORAGE_FAILURE, and callers treated the key as absent.
 * Only ENOENT means the record is absent; any other open failure is a
 * storage fault.
 *
 * Must run as a non-root user: chmod 000 is the denial mechanism.
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
#include <unistd.h>
#include <sys/stat.h>

#include <psa/crypto.h>

#define WOLFPSA_TEST_STORE_NAME "psa_key_%016lx_0000000000000000"

static int test_read_open_error(const char *store_dir, psa_key_id_t key_id)
{
    char record[512];
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_status_t st;
    int ok = 0;

    if (snprintf(record, sizeof(record), "%s/" WOLFPSA_TEST_STORE_NAME,
                 store_dir, (unsigned long)key_id) >= (int)sizeof(record)) {
        printf("FAIL read-open: record path too long\n");
        return 1;
    }

    /* The key must be readable while the record is intact. */
    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL read-open: pre-chmod attributes status=%d\n", (int)st);
        return 1;
    }

    if (chmod(record, S_IRUSR | S_IWUSR) != 0) {
        printf("FAIL read-open: chmod 0600 setup failed\n");
        return 1;
    }
    if (chmod(record, 0) != 0) {
        printf("FAIL read-open: chmod 000 failed (run as non-root?)\n");
        return 1;
    }

    /* Record exists but cannot be opened: a storage fault, not a
     * missing key. */
    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL read-open: blocked record status=%d expected=%d\n",
               (int)st, (int)PSA_ERROR_STORAGE_FAILURE);
        (void)chmod(record, S_IRUSR | S_IWUSR);
        return 1;
    }

    /* The failed read must not have damaged the record: restoring
     * access restores the key. */
    if (chmod(record, S_IRUSR | S_IWUSR) != 0) {
        printf("FAIL read-open: chmod restore failed\n");
        return 1;
    }
    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL read-open: post-restore attributes status=%d\n",
               (int)st);
        return 1;
    }

    /* A genuinely absent record still maps to "not available". */
    st = psa_get_key_attributes(0x10000001, &got);
    if (st != PSA_ERROR_INVALID_HANDLE) {
        printf("FAIL read-open: absent key status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_INVALID_HANDLE);
        return 1;
    }

    ok = 1;

    return ok ? 0 : 1;
}

int main(void)
{
    char store_dir[] = "/tmp/wolfpsa_store_read_open_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ret = 1;

    if (mkdtemp(store_dir) == NULL) {
        printf("psa_store_read_open_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("psa_store_read_open_test: setenv failed\n");
        return 1;
    }
    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("psa_store_read_open_test: psa_crypto_init failed\n");
        return 1;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_PERSISTENCE_DEFAULT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_SUCCESS || key_id == PSA_KEY_ID_NULL) {
        printf("psa_store_read_open_test: import failed status=%d\n",
               (int)st);
        goto out;
    }

    ret = test_read_open_error(store_dir, key_id);

    (void)psa_destroy_key(key_id);

out:
    (void)rmdir(store_dir); /* best effort; record removed by destroy */

    if (ret != 0) {
        printf("PSA store read-open test: FAIL\n");
        return 1;
    }

    printf("PSA store read-open test: OK\n");
    return 0;
}
