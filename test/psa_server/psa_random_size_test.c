/* psa_random_size_test.c
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

#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#include <wolfpsa/psa/crypto.h>

int main(void)
{
    size_t huge;
    uint8_t* buf;
    psa_status_t st;

    if (SIZE_MAX <= UINT32_MAX) {
        printf("SKIP psa_random_size_test requires size_t wider than 32 bits\n");
        return 0;
    }

    huge = (size_t)UINT32_MAX + 1u;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    buf = (uint8_t*)mmap(NULL, huge, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        printf("SKIP mmap failed for size=%zu\n", huge);
        return 0;
    }

    st = psa_generate_random(buf, huge);
    munmap(buf, huge);

    if (st == PSA_SUCCESS) {
        printf("FAIL psa_generate_random unexpectedly succeeded for size=%zu\n",
               huge);
        return 1;
    }

    printf("PSA random size test: OK (status=%d)\n", (int)st);
    return 0;
}
