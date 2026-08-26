/* Regression: ECDSA public-key verification must honour the PSA
 * curve family recorded in the key attributes, not fall back to the
 * wolfCrypt default curve for the coordinate size.
 *
 * Before the fix, a same-size non-default family (secp256k1,
 * Brainpool-P256) public key was imported on the default curve, so
 * verification of a valid signature failed.
 *
 * Requires a build with HAVE_ECC_KOBLITZ; without it this test is a
 * no-op.
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_ECC_KOBLITZ

#define HASH_LEN  32
#define PUB_LEN   65
#define SIG_LEN   64

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

static void test_curve_family(psa_key_type_t pair_type,
                              psa_key_type_t pub_type, size_t bits)
{
    psa_status_t status;
    psa_key_attributes_t attrs;
    psa_key_id_t pair = PSA_KEY_ID_NULL;
    psa_key_id_t pub  = PSA_KEY_ID_NULL;
    uint8_t hash[HASH_LEN];
    uint8_t signature[SIG_LEN];
    size_t signature_length = 0;
    uint8_t public_key[PUB_LEN];
    size_t public_key_length = 0;

    /* Stand in for a SHA-256 digest of some message; psa_sign_hash and
     * psa_verify_hash both take the digest itself. */
    memset(hash, 0x5a, sizeof(hash));

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, pair_type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs,
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    status = psa_generate_key(&attrs, &pair);
    expect(status, PSA_SUCCESS, "generate key pair");
    if (status != PSA_SUCCESS) {
        return;
    }

    status = psa_export_public_key(pair, public_key, sizeof(public_key),
                                   &public_key_length);
    expect(status, PSA_SUCCESS, "export public key from pair");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    status = psa_sign_hash(pair, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                           sizeof(hash), signature, sizeof(signature),
                           &signature_length);
    expect(status, PSA_SUCCESS, "sign hash");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, pub_type);
    psa_set_key_bits(&attrs, bits);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    status = psa_import_key(&attrs, public_key, public_key_length, &pub);
    expect(status, PSA_SUCCESS, "import public key");
    if (status != PSA_SUCCESS) {
        goto cleanup;
    }

    /* The point of the test: the standalone public key must verify a
     * signature made by its pair, on the family the key declares. */
    status = psa_verify_hash(pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                             sizeof(hash), signature, signature_length);
    expect(status, PSA_SUCCESS, "verify with standalone public key");

cleanup:
    psa_destroy_key(pub);
    psa_destroy_key(pair);
}

int main(void)
{
    psa_status_t status;

    status = psa_crypto_init();
    expect(status, PSA_SUCCESS, "psa_crypto_init");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    test_curve_family(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1),
                      PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1),
                      256);
    if (failures == 0) {
        printf("verify-curve tests: all passed\n");
        return 0;
    }
    printf("verify-curve tests: %d failure(s)\n", failures);
    return 1;
}

#else /* !HAVE_ECC_KOBLITZ */

int main(void)
{
    printf("verify-curve tests: skipped (no HAVE_ECC_KOBLITZ)\n");
    return 0;
}

#endif /* HAVE_ECC_KOBLITZ */
