/* Regression: Weierstrass ECDH must import the peer public key
 * on the curve declared by the local key, not on the wolfCrypt default
 * curve for the coordinate size.
 *
 * Before the fix, a same-size non-default family (secp256k1,
 * Brainpool-P256) peer key was imported on the wrong curve, so key
 * agreement failed or used the wrong domain parameters.
 *
 * Requires a build with HAVE_ECC_KOBLITZ; without it this test is a
 * no-op. test/Makefile compiles with -DWOLFSSL_USER_SETTINGS and the
 * same USER_SETTINGS_PATH as the library build, so the gate below
 * tracks the libwolfpsa configuration.
 */

#include <psa/crypto.h>
#ifdef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <stdio.h>
#include <string.h>

#ifdef HAVE_ECC_KOBLITZ

#define PUB_LEN   65
#define SECRET_LEN 32

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

static void test_ecdh_family(psa_key_type_t pair_type, size_t bits)
{
    psa_status_t status;
    psa_key_attributes_t attrs;
    psa_key_id_t a = PSA_KEY_ID_NULL;
    psa_key_id_t b = PSA_KEY_ID_NULL;
    uint8_t pub_a[PUB_LEN];
    size_t pub_a_len = 0;
    uint8_t pub_b[PUB_LEN];
    size_t pub_b_len = 0;
    uint8_t secret_a[SECRET_LEN];
    size_t secret_a_len = 0;
    uint8_t secret_b[SECRET_LEN];
    size_t secret_b_len = 0;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, pair_type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);
    status = psa_generate_key(&attrs, &a);
    expect(status, PSA_SUCCESS, "generate key pair A");
    if (status != PSA_SUCCESS) {
        return;
    }

    status = psa_generate_key(&attrs, &b);
    expect(status, PSA_SUCCESS, "generate key pair B");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_export_public_key(a, pub_a, sizeof(pub_a), &pub_a_len);
    expect(status, PSA_SUCCESS, "export public key A");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }
    status = psa_export_public_key(b, pub_b, sizeof(pub_b), &pub_b_len);
    expect(status, PSA_SUCCESS, "export public key B");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* The point of the test: both directions of the raw ECDH must
     * succeed and agree, on the family the keys declare. */
    status = psa_raw_key_agreement(PSA_ALG_ECDH, a, pub_b,
                                   pub_b_len, secret_a, sizeof(secret_a),
                                   &secret_a_len);
    expect(status, PSA_SUCCESS, "raw key agreement A with peer B");
    status = psa_raw_key_agreement(PSA_ALG_ECDH, b, pub_a,
                                   pub_a_len, secret_b, sizeof(secret_b),
                                   &secret_b_len);
    expect(status, PSA_SUCCESS, "raw key agreement B with peer A");
    if ((status == PSA_SUCCESS) &&
        (secret_a_len != secret_b_len ||
         memcmp(secret_a, secret_b, secret_a_len) != 0)) {
        printf("FAIL: shared secrets differ\n");
        failures++;
    }

cleanup:
    psa_destroy_key(b);
    psa_destroy_key(a);
}

int main(void)
{
    psa_status_t status;

    status = psa_crypto_init();
    expect(status, PSA_SUCCESS, "psa_crypto_init");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    test_ecdh_family(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1), 256);
    if (failures == 0) {
        printf("ecdh-curve tests: all passed\n");
        return 0;
    }
    printf("ecdh-curve tests: %d failure(s)\n", failures);
    return 1;
}

#else /* !HAVE_ECC_KOBLITZ */

int main(void)
{
    printf("ecdh-curve tests: skipped (no HAVE_ECC_KOBLITZ)\n");
    return 0;
}

#endif /* HAVE_ECC_KOBLITZ */
