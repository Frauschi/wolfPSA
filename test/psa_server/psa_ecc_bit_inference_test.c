#include "psa_api_test_user_settings.h"

#ifndef WOLFSSL_USER_SETTINGS
#define WOLFSSL_USER_SETTINGS
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <stdio.h>
#include <string.h>

#include <wolfpsa/psa/crypto.h>

static int test_public_key_bits(void)
{
    uint8_t pub[133];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    memset(pub, 0, sizeof(pub));
    pub[0] = 0x04;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);

    st = psa_import_key(&attrs, pub, sizeof(pub), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL public import status=%d\n", (int)st);
        return 1;
    }

    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL public attrs status=%d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return 1;
    }

    if (psa_get_key_bits(&got) != 521) {
        printf("FAIL public bits=%u expected=521\n",
               (unsigned)psa_get_key_bits(&got));
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    return 0;
}

static int test_private_key_bits(void)
{
    uint8_t priv[66];
    psa_key_attributes_t attrs = psa_key_attributes_init();
    psa_key_attributes_t got = psa_key_attributes_init();
    psa_key_id_t key_id = PSA_KEY_ID_NULL;
    psa_status_t st;

    memset(priv, 0, sizeof(priv));
    priv[sizeof(priv) - 1] = 1;

    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_EXPORT);

    st = psa_import_key(&attrs, priv, sizeof(priv), &key_id);
    if (st != PSA_SUCCESS) {
        printf("FAIL private import status=%d\n", (int)st);
        return 1;
    }

    st = psa_get_key_attributes(key_id, &got);
    if (st != PSA_SUCCESS) {
        printf("FAIL private attrs status=%d\n", (int)st);
        (void)psa_destroy_key(key_id);
        return 1;
    }

    if (psa_get_key_bits(&got) != 521) {
        printf("FAIL private bits=%u expected=521\n",
               (unsigned)psa_get_key_bits(&got));
        (void)psa_destroy_key(key_id);
        return 1;
    }

    (void)psa_destroy_key(key_id);
    return 0;
}

int main(void)
{
    psa_status_t st = psa_crypto_init();
    if (st != PSA_SUCCESS) {
        printf("FAIL psa_crypto_init status=%d\n", (int)st);
        return 1;
    }

    if (test_public_key_bits() != 0) {
        return 1;
    }
    if (test_private_key_bits() != 0) {
        return 1;
    }

    printf("PSA ECC bit inference test: OK\n");
    return 0;
}
