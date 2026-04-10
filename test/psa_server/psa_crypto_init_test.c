#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <stdio.h>

#include <wolfpsa/psa/crypto.h>

static int g_wolfcrypt_init_calls;
static int g_wolfcrypt_init_result;

int __wrap_wolfCrypt_Init(void)
{
    g_wolfcrypt_init_calls++;
    return g_wolfcrypt_init_result;
}

static int expect_status(const char* label, psa_status_t status, psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s status=%d expected=%d\n", label, (int)status, (int)expected);
        return 1;
    }

    return 0;
}

int main(void)
{
    psa_status_t st;

    g_wolfcrypt_init_calls = 0;
    g_wolfcrypt_init_result = RNG_FAILURE_E;

    st = psa_crypto_init();
    if (expect_status("psa_crypto_init rng failure", st,
                      PSA_ERROR_INSUFFICIENT_ENTROPY) != 0) {
        return 1;
    }
    if (g_wolfcrypt_init_calls != 1) {
        printf("FAIL wolfCrypt_Init calls=%d expected=1\n", g_wolfcrypt_init_calls);
        return 1;
    }

    g_wolfcrypt_init_result = 0;
    st = psa_crypto_init();
    if (expect_status("psa_crypto_init success", st, PSA_SUCCESS) != 0) {
        return 1;
    }
    if (g_wolfcrypt_init_calls != 2) {
        printf("FAIL wolfCrypt_Init calls=%d expected=2\n", g_wolfcrypt_init_calls);
        return 1;
    }

    printf("PSA crypto init test: OK\n");
    return 0;
}
