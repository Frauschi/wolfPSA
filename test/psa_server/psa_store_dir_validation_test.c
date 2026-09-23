/* psa_store_dir_validation_test.c
 *
 * Regression tests for the privacy rules the POSIX store applies to its
 * store location, all driven through psa_import_key/psa_get_key_attributes:
 *
 *   - the store directory itself, on the write path and the read path
 *   - a writable parent, and a writable grandparent
 *   - a relative store path, which must reach the same verdict however it
 *     is spelled
 *   - a store directory created here and then refused, which must not be
 *     left behind
 *
 * The ownership branch is not exercised: a non-root test user cannot create
 * a directory owned by someone else. The mode branch carries the gate.
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

static char g_saved_token[512];
static int g_had_token;

static void token_save(void)
{
    const char *t = getenv("WOLFPSA_TOKEN_PATH");

    g_had_token = (t != NULL) && (strlen(t) < sizeof(g_saved_token));
    if (g_had_token) {
        strcpy(g_saved_token, t);
    }
}

static void token_restore(void)
{
    if (g_had_token) {
        (void)setenv("WOLFPSA_TOKEN_PATH", g_saved_token, 1);
    }
    else {
        (void)unsetenv("WOLFPSA_TOKEN_PATH");
    }
}

static int test_dir(const char *label, mode_t mode, psa_status_t expected)
{
    char dir[] = "/tmp/wolfpsa_store_dir_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
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
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

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
    token_restore();
    return ok ? 0 : 1;
}

/* Reading a record back is the substitution that matters: a record written
 * while the directory was private must not be read back once the directory
 * has become writable by a local peer. */
static int test_read_back_from_unsafe_dir(void)
{
    char dir[] = "/tmp/wolfpsa_store_dir_read_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(dir) == NULL) {
        printf("FAIL dir-read-back: mkdtemp failed\n");
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("FAIL dir-read-back: setenv failed\n");
        (void)rmdir(dir);
        return 1;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    /* Written while the directory is still the 0700 mkdtemp created. */
    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL dir-read-back: import status=%d\n", (int)st);
        goto out;
    }
    if (psa_get_key_attributes(key_id, &got) != PSA_SUCCESS) {
        printf("FAIL dir-read-back: key not readable while dir is private\n");
        goto out;
    }

    if (chmod(dir, 0775) != 0) {
        printf("FAIL dir-read-back: chmod failed\n");
        goto out;
    }
    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL dir-read-back: status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_STORAGE_FAILURE);
        goto out;
    }

    ok = 1;

out:
    (void)chmod(dir, 0700);
    (void)psa_destroy_key(key_id);
    (void)rmdir(dir);
    token_restore();
    return ok ? 0 : 1;
}

/* A private store directory under a parent a local peer can write is not
 * safe: the peer renames the parent and substitutes the whole store. */
static int test_writable_parent_rejected(void)
{
    char parent[] = "/tmp/wolfpsa_store_parent_XXXXXX";
    char dir[sizeof(parent) + 8];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(parent) == NULL) {
        printf("FAIL parent-writable: mkdtemp failed\n");
        return 1;
    }
    (void)snprintf(dir, sizeof(dir), "%s/store", parent);
    if (mkdir(dir, 0700) != 0) {
        printf("FAIL parent-writable: mkdir failed\n");
        (void)rmdir(parent);
        return 1;
    }
    /* Writable by other, and not sticky, so a peer can rename "store". */
    if (chmod(parent, 0707) != 0) {
        printf("FAIL parent-writable: chmod failed\n");
        goto out;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("FAIL parent-writable: setenv failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL parent-writable: import status=%d expected=%d\n",
               (int)st, (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }
    ok = 1;

out:
    (void)chmod(parent, 0700);
    (void)rmdir(dir);
    (void)rmdir(parent);
    token_restore();
    return ok ? 0 : 1;
}

/* A relative store path is resolved against the working directory, so "x" and
 * "./x" reach the same verdict. Restores the cwd and WOLFPSA_TOKEN_PATH it
 * changes, so it carries no ordering dependency on the tests around it. */
static int test_relative_path_checks_cwd(void)
{
    char dir[] = "/tmp/wolfpsa_store_rel_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    char cwd[512];
    psa_status_t st;
    int ok = 0;

    token_save();

    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        printf("FAIL relative-cwd: getcwd failed\n");
        return 1;
    }
    if (mkdtemp(dir) == NULL) {
        printf("FAIL relative-cwd: mkdtemp failed\n");
        return 1;
    }
    if (chdir(dir) != 0) {
        printf("FAIL relative-cwd: chdir failed\n");
        (void)rmdir(dir);
        return 1;
    }
    if (mkdir(".store", 0700) != 0 || chmod(dir, 0707) != 0) {
        printf("FAIL relative-cwd: setup failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    /* The store directory itself is private; the cwd holding it is not. */
    if (setenv("WOLFPSA_TOKEN_PATH", ".store", 1) != 0) {
        printf("FAIL relative-cwd: setenv failed\n");
        goto out;
    }
    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL relative-cwd \".store\": status=%d expected=%d\n",
               (int)st, (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }

    if (setenv("WOLFPSA_TOKEN_PATH", "./.store", 1) != 0) {
        printf("FAIL relative-cwd: setenv failed\n");
        goto out;
    }
    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL relative-cwd \"./.store\": status=%d expected=%d\n",
               (int)st, (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }
    ok = 1;

out:
    (void)chmod(dir, 0700);
    (void)rmdir(".store");
    if (chdir(cwd) != 0) {
        printf("FAIL relative-cwd: restoring the cwd failed\n");
        ok = 0;
    }
    (void)rmdir(dir);
    token_restore();
    return ok ? 0 : 1;
}

/* The ancestor rule applies at any depth and on the read path: a record
 * written under a safe tree must stop being readable once a grandparent
 * becomes writable by a local peer. */
static int test_grandparent_on_read_path(void)
{
    char top[] = "/tmp/wolfpsa_store_deep_XXXXXX";
    char mid[sizeof(top) + 8];
    char leaf[sizeof(top) + 16];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(top) == NULL) {
        printf("FAIL grandparent: mkdtemp failed\n");
        return 1;
    }
    (void)snprintf(mid, sizeof(mid), "%s/mid", top);
    (void)snprintf(leaf, sizeof(leaf), "%s/store", mid);
    if (mkdir(mid, 0700) != 0 || mkdir(leaf, 0700) != 0) {
        printf("FAIL grandparent: mkdir failed\n");
        goto out;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", leaf, 1) != 0) {
        printf("FAIL grandparent: setenv failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL grandparent: import status=%d\n", (int)st);
        goto out;
    }
    if (psa_get_key_attributes(key_id, &got) != PSA_SUCCESS) {
        printf("FAIL grandparent: unreadable while the tree is private\n");
        goto out;
    }

    /* Two levels up from the store directory, and not sticky. */
    if (chmod(top, 0707) != 0) {
        printf("FAIL grandparent: chmod failed\n");
        goto out;
    }
    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL grandparent: read status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_STORAGE_FAILURE);
        goto out;
    }
    ok = 1;

out:
    (void)chmod(top, 0700);
    (void)psa_destroy_key(key_id);
    (void)rmdir(leaf);
    (void)rmdir(mid);
    (void)rmdir(top);
    token_restore();
    return ok ? 0 : 1;
}

/* The store directory is created here and then refused by the ancestor
 * check, so the rollback must not leave an empty directory behind. */
static int test_created_then_refused_is_removed(void)
{
    char parent[] = "/tmp/wolfpsa_store_roll_XXXXXX";
    char dir[sizeof(parent) + 8];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(parent) == NULL) {
        printf("FAIL rollback: mkdtemp failed\n");
        return 1;
    }
    (void)snprintf(dir, sizeof(dir), "%s/store", parent);
    /* Writable by other and not sticky, so the store directory that
     * psa_import_key creates below is refused straight after creation. */
    if (chmod(parent, 0707) != 0) {
        printf("FAIL rollback: chmod failed\n");
        goto out;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("FAIL rollback: setenv failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL rollback: import status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }
    if (access(dir, F_OK) == 0) {
        printf("FAIL rollback: refused store directory was left behind\n");
        goto out;
    }
    ok = 1;

out:
    (void)chmod(parent, 0700);
    (void)rmdir(dir);
    (void)rmdir(parent);
    token_restore();
    return ok ? 0 : 1;
}

/* The store is reached through a symlink whose own directory a peer can
 * write. The real tree is private, so only walking the resolved chain would
 * accept it, while the peer can repoint the link at a store of their own. */
static int test_symlink_holder_must_be_private(void)
{
    char top[] = "/tmp/wolfpsa_store_link_XXXXXX";
    char real_mid[sizeof(top) + 16];
    char real_store[sizeof(top) + 24];
    char holder[sizeof(top) + 16];
    char link_path[sizeof(top) + 24];
    char token[sizeof(top) + 32];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(top) == NULL) {
        printf("FAIL symlink-holder: mkdtemp failed\n");
        return 1;
    }
    (void)snprintf(real_mid, sizeof(real_mid), "%s/real", top);
    (void)snprintf(real_store, sizeof(real_store), "%s/real/store", top);
    (void)snprintf(holder, sizeof(holder), "%s/holder", top);
    (void)snprintf(link_path, sizeof(link_path), "%s/holder/link", top);
    (void)snprintf(token, sizeof(token), "%s/holder/link/store", top);

    if (mkdir(real_mid, 0700) != 0 || mkdir(real_store, 0700) != 0 ||
        mkdir(holder, 0700) != 0 || symlink(real_mid, link_path) != 0) {
        printf("FAIL symlink-holder: setup failed\n");
        goto out;
    }
    /* Only the directory holding the symlink is writable by others. */
    if (chmod(holder, 0707) != 0) {
        printf("FAIL symlink-holder: chmod failed\n");
        goto out;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", token, 1) != 0) {
        printf("FAIL symlink-holder: setenv failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL symlink-holder: import status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }
    ok = 1;

out:
    (void)chmod(holder, 0700);
    (void)unlink(link_path);
    (void)rmdir(holder);
    (void)rmdir(real_store);
    (void)rmdir(real_mid);
    (void)rmdir(top);
    token_restore();
    return ok ? 0 : 1;
}

/* A store directory that already existed must never be removed, however the
 * check comes out: the rollback is only for one this call created. */
static int test_existing_store_dir_is_kept(void)
{
    char parent[] = "/tmp/wolfpsa_store_keep_XXXXXX";
    char dir[sizeof(parent) + 8];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t key_data[16];
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int ok = 0;

    token_save();
    if (mkdtemp(parent) == NULL) {
        printf("FAIL keep-existing: mkdtemp failed\n");
        return 1;
    }
    (void)snprintf(dir, sizeof(dir), "%s/store", parent);
    if (mkdir(dir, 0700) != 0 || chmod(parent, 0707) != 0) {
        printf("FAIL keep-existing: setup failed\n");
        goto out;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", dir, 1) != 0) {
        printf("FAIL keep-existing: setenv failed\n");
        goto out;
    }

    memset(key_data, 0x42, sizeof(key_data));
    psa_set_key_type(&attrs, PSA_KEY_TYPE_RAW_DATA);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);

    st = psa_import_key(&attrs, key_data, sizeof(key_data), &key_id);
    if (st != PSA_ERROR_STORAGE_FAILURE) {
        printf("FAIL keep-existing: import status=%d expected=%d\n", (int)st,
               (int)PSA_ERROR_STORAGE_FAILURE);
        (void)psa_destroy_key(key_id);
        goto out;
    }
    if (access(dir, F_OK) != 0) {
        printf("FAIL keep-existing: pre-existing store directory removed\n");
        goto out;
    }
    ok = 1;

out:
    (void)chmod(parent, 0700);
    (void)rmdir(dir);
    (void)rmdir(parent);
    token_restore();
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
    /* The ownership half of the predicate (euid-owned or root-owned accepted,
     * anything else rejected) is not covered here: creating a directory owned
     * by a third uid needs privileges CI does not have. */
    ret |= test_read_back_from_unsafe_dir();
    ret |= test_writable_parent_rejected();
    ret |= test_relative_path_checks_cwd();
    ret |= test_grandparent_on_read_path();
    ret |= test_created_then_refused_is_removed();
    ret |= test_symlink_holder_must_be_private();
    ret |= test_existing_store_dir_is_kept();

    if (ret != 0) {
        printf("PSA store dir validation test: FAIL\n");
        return 1;
    }

    printf("PSA store dir validation test: OK\n");
    return 0;
}
