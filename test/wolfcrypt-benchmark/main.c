/* main.c
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
#include <dlfcn.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/psa/psa.h>
#include <wolfcrypt/benchmark/benchmark.h>

static void* load_wolfpsa(void)
{
    const char* lib = getenv("WOLFPSA_LIB");
    void* handle;

    if (lib == NULL || lib[0] == '\0')
        lib = "libwolfpsa.so";

    handle = dlopen(lib, RTLD_NOW | RTLD_GLOBAL);
    if (handle == NULL) {
        fprintf(stderr, "wolfpsa: dlopen(%s) failed: %s\n", lib, dlerror());
        return NULL;
    }

    return handle;
}

int main(int argc, char** argv)
{
    void* wolfpsa_handle;
    int ret;

#if !defined(WOLFSSL_HAVE_PSA)
    fprintf(stderr, "ERROR: WOLFSSL_HAVE_PSA is not enabled in this build.\n");
    return EXIT_FAILURE;
#endif

    wolfpsa_handle = load_wolfpsa();
    if (wolfpsa_handle == NULL)
        return EXIT_FAILURE;

    /* Initialize wolfCrypt/PSA once so we can register the PSA CryptoCb. */
    ret = wolfCrypt_Init();
    if (ret != 0) {
        fprintf(stderr, "wolfCrypt_Init failed: %d\n", ret);
        dlclose(wolfpsa_handle);
        return EXIT_FAILURE;
    }

    ret = wolfcrypt_benchmark_main(argc, argv);

    wolfCrypt_Cleanup();
    dlclose(wolfpsa_handle);

    return ret;
}
