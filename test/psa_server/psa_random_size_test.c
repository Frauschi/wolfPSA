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
    size_t huge = (size_t)UINT32_MAX + 1u;
    uint8_t* buf;
    psa_status_t st;

    st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    buf = (uint8_t*)mmap(NULL, huge, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        return 2;
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
