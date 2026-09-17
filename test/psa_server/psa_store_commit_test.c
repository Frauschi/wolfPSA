/* psa_store_commit_test.c
 *
 * Regression test: wolfPSA_Store_Close() was void, so a failure of the
 * atomic commit (renaming the temporary record onto the final name) or of
 * the file close was silently discarded. A persistent key write could
 * report success while the record was never stored, and the abort path
 * after a failed close was the only cleanup. Close now returns
 * WOLFPSA_STORE_IO_ERROR when the commit or the close fails, after
 * aborting the temporary record.
 *
 * The test drives the store backend directly: through the public API a
 * commit failure is not reachable deterministically, because the import
 * probe fails first on the same condition. It links the static library,
 * because the shared library exports only the psa_* API.
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
#include <dirent.h>
#include <unistd.h>

#include <psa_store.h>

#define WOLFPSA_TEST_RECORD "psa_key_%016lx_0000000000000000"

static int count_entries(const char *dir)
{
    DIR *d;
    struct dirent *e;
    int n = 0;

    d = opendir(dir);
    if (d == NULL) {
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0) {
            n++;
        }
    }
    (void)closedir(d);

    return n;
}

static int test_commit_failure(const char *dir, unsigned long id)
{
    char record[512];
    unsigned char data[16];
    void *store = NULL;
    int ret;
    int entries;

    if (snprintf(record, sizeof(record), "%s/" WOLFPSA_TEST_RECORD, dir, id)
        >= (int)sizeof(record)) {
        printf("FAIL commit-fail: record path too long\n");
        return 1;
    }
    if (mkdir(record, 0700) != 0) {
        printf("FAIL commit-fail: mkdir record dir failed\n");
        return 1;
    }

    memset(data, 0x42, sizeof(data));
    ret = wolfPSA_Store_OpenSz(WOLFPSA_STORE_KEY, id, 0, 0, (int)sizeof(data),
                               &store);
    if (ret != WOLFPSA_STORE_OK) {
        printf("FAIL commit-fail: open status=%d\n", ret);
        goto out;
    }
    ret = wolfPSA_Store_Write(store, data, (int)sizeof(data));
    if (ret != (int)sizeof(data)) {
        printf("FAIL commit-fail: write status=%d\n", ret);
        wolfPSA_Store_Close(store);
        goto out;
    }

    /* The rename onto a directory must fail, and the failure must be
     * reported. */
    ret = wolfPSA_Store_Close(store);
    if (ret != WOLFPSA_STORE_IO_ERROR) {
        printf("FAIL commit-fail: close status=%d expected=%d\n", ret,
               WOLFPSA_STORE_IO_ERROR);
        goto out;
    }

    /* The failed commit must not leave the temporary record behind. */
    entries = count_entries(dir);
    if (entries != 1) {
        printf("FAIL commit-fail: %d entries left in store dir, expected 1\n",
               entries);
        goto out;
    }

    (void)rmdir(record);
    return 0;

out:
    (void)rmdir(record);
    return 1;
}

static int test_commit_success(const char *dir, unsigned long id)
{
    char record[512];
    unsigned char readback[16];
    unsigned char data[16];
    void *store = NULL;
    struct stat st;
    int ret;

    if (snprintf(record, sizeof(record), "%s/" WOLFPSA_TEST_RECORD, dir, id)
        >= (int)sizeof(record)) {
        printf("FAIL commit-ok: record path too long\n");
        return 1;
    }

    memset(data, 0x24, sizeof(data));
    ret = wolfPSA_Store_OpenSz(WOLFPSA_STORE_KEY, id, 0, 0, (int)sizeof(data),
                               &store);
    if (ret != WOLFPSA_STORE_OK) {
        printf("FAIL commit-ok: open status=%d\n", ret);
        return 1;
    }
    ret = wolfPSA_Store_Write(store, data, (int)sizeof(data));
    if (ret != (int)sizeof(data)) {
        printf("FAIL commit-ok: write status=%d\n", ret);
        wolfPSA_Store_Close(store);
        return 1;
    }
    ret = wolfPSA_Store_Close(store);
    if (ret != WOLFPSA_STORE_OK) {
        printf("FAIL commit-ok: close status=%d\n", ret);
        return 1;
    }

    if (stat(record, &st) != 0 || !S_ISREG(st.st_mode)) {
        printf("FAIL commit-ok: record missing after commit\n");
        return 1;
    }

    /* The committed record must be readable back. */
    ret = wolfPSA_Store_Open(WOLFPSA_STORE_KEY, id, 0, 1, &store);
    if (ret != WOLFPSA_STORE_OK) {
        printf("FAIL commit-ok: reopen status=%d\n", ret);
        return 1;
    }
    ret = wolfPSA_Store_Read(store, readback, (int)sizeof(readback));
    if (ret != (int)sizeof(readback) ||
        memcmp(readback, data, sizeof(data)) != 0) {
        printf("FAIL commit-ok: readback mismatch (ret=%d)\n", ret);
        wolfPSA_Store_Close(store);
        return 1;
    }
    ret = wolfPSA_Store_Close(store);
    if (ret != WOLFPSA_STORE_OK) {
        printf("FAIL commit-ok: read close status=%d\n", ret);
        return 1;
    }

    (void)remove(record);
    return 0;
}

int main(void)
{
    char dir[] = "/tmp/wolfpsa_store_commit_XXXXXX";
    int ret = 0;

    if (mkdtemp(dir) == NULL) {
        printf("psa_store_commit_test: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("psa_store_commit_test: setenv failed\n");
        return 1;
    }

    ret |= test_commit_failure(dir, 1);
    ret |= test_commit_success(dir, 2);

    (void)rmdir(dir);

    if (ret != 0) {
        printf("PSA store commit test: FAIL\n");
        return 1;
    }

    printf("PSA store commit test: OK\n");
    return 0;
}
