/* psa_pqc_export_seed_test.c
 *
 * Regression test: psa_export_public_key() forwarded the
 * stored seed of an ML-DSA/ML-KEM key pair to the expansion helpers
 * without validating the stored length. The helpers consume fixed
 * 32-byte / 64-byte seeds, so a corrupted persistent record with a
 * shorter seed caused an out-of-bounds read.
 *
 * The defect is only reachable through a corrupted store record (all
 * import paths enforce the seed length), so this test imports a valid
 * key, corrupts the on-disk record's data length field, and expects
 * PSA_ERROR_DATA_INVALID from the export instead of the out-of-bounds
 * expansion.
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
#include <fcntl.h>
#include <unistd.h>

#include <psa/crypto.h>

#define WOLFPSA_ATTR_SIZE (sizeof(psa_key_type_t) + sizeof(psa_key_bits_t) + \
                           sizeof(psa_key_usage_t) + sizeof(psa_algorithm_t) + \
                           sizeof(psa_key_lifetime_t))

/* Truncate the on-disk key record to the given seed length: rewrite the
 * stored data length field and cut the file after that many data bytes. */
static int truncate_store_record(const char* dir, psa_key_id_t key_id,
                                 size_t new_len)
{
    char path[512];
    uint8_t* rec = NULL;
    size_t rec_len;
    size_t total;
    int fd;
    int ok = 0;

    if (snprintf(path, sizeof(path), "%s/psa_key_%016lx_%016lx", dir,
                 (unsigned long)key_id, 0UL) >= (int)sizeof(path)) {
        return 1;
    }

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("FAIL open store record %s\n", path);
        goto out;
    }

    rec_len = 0;
    for (;;) {
        ssize_t n;

        if (rec_len >= sizeof(size_t) * 4) {
            break;
        }
        rec = (uint8_t*)realloc(rec, rec_len + 4096);
        if (rec == NULL) {
            close(fd);
            goto out;
        }
        n = read(fd, rec + rec_len, 4096);
        if (n <= 0) {
            break;
        }
        rec_len += (size_t)n;
    }
    close(fd);

    if (rec == NULL ||
        rec_len < WOLFPSA_ATTR_SIZE + sizeof(size_t) + new_len) {
        printf("FAIL store record too short (%zu)\n", rec_len);
        goto out;
    }

    total = WOLFPSA_ATTR_SIZE + sizeof(size_t) + new_len;
    memcpy(rec + WOLFPSA_ATTR_SIZE, &new_len, sizeof(size_t));

    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        goto out;
    }
    if (write(fd, rec, total) != (ssize_t)total) {
        close(fd);
        goto out;
    }
    close(fd);
    ok = 1;

out:
    free(rec);
    return ok ? 0 : 1;
}

static int test_corrupted_seed(psa_key_type_t type, psa_key_bits_t bits,
                               size_t seed_size, size_t corrupt_len,
                               psa_key_id_t key_id, const char* label)
{
    char store_dir[] = "/tmp/wolfpsa_pqc_seed_XXXXXX";
    psa_key_attributes_t attrs = psa_key_attributes_init();
    static uint8_t seed[64];
    uint8_t pub[2592];
    size_t pub_len = 0;
    psa_key_id_t imported_id = PSA_KEY_ID_NULL;
    psa_status_t st;
    int i;
    int ok = 0;

    if (mkdtemp(store_dir) == NULL) {
        printf("FAIL %s mkdtemp\n", label);
        return 1;
    }
    if (setenv("WOLFPSA_TOKEN_PATH", store_dir, 1) != 0) {
        printf("FAIL %s setenv\n", label);
        return 1;
    }

    memset(seed, 0x37, sizeof(seed));

    psa_set_key_type(&attrs, type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);
    psa_set_key_lifetime(&attrs, PSA_KEY_LIFETIME_PERSISTENT);
    psa_set_key_id(&attrs, key_id);

    st = psa_import_key(&attrs, seed, seed_size, &imported_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s import status=%d\n", label, (int)st);
        goto done;
    }

    /* A well-formed record still exports. */
    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (st != PSA_SUCCESS) {
        printf("FAIL %s valid export status=%d\n", label, (int)st);
        goto destroy;
    }

    /* Corrupt the stored seed length, then export again: the record no
     * longer holds a full seed and must be reported invalid, not read
     * out of bounds. */
    if (truncate_store_record(store_dir, key_id, corrupt_len) != 0) {
        goto destroy;
    }

    st = psa_export_public_key(key_id, pub, sizeof(pub), &pub_len);
    if (st != PSA_ERROR_DATA_INVALID) {
        printf("FAIL %s corrupted export status=%d expected=%d\n", label,
               (int)st, (int)PSA_ERROR_DATA_INVALID);
        goto destroy;
    }

    ok = 1;

destroy:
    (void)psa_destroy_key(key_id);

done:
    for (i = 0; i < (int)sizeof(seed); i++) {
        seed[i] = 0;
    }
    return ok ? 0 : 1;
}

int main(void)
{
    int rc = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init\n");
        return 1;
    }

    rc |= test_corrupted_seed(PSA_KEY_TYPE_ML_DSA_KEY_PAIR, 128, 32, 16,
                              PSA_KEY_ID_USER_MIN + 1, "mldsa-44");
    rc |= test_corrupted_seed(PSA_KEY_TYPE_ML_KEM_KEY_PAIR, 512, 64, 8,
                              PSA_KEY_ID_USER_MIN + 2, "mlkem-512");

    if (rc != 0) {
        printf("PSA pqcseedlen test: FAIL\n");
        return 1;
    }

    printf("PSA pqcseedlen test: OK\n");
    return 0;
}
