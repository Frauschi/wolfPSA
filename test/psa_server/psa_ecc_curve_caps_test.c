/* Regression: wc_psa_get_ecc_curve_id must respect the
 * compile-time curve capability flags, like the rest of the key
 * validation does. In a build without HAVE_ECC_KOBLITZ or
 * HAVE_ECC_BRAINPOOL, operations on those families must fail with a clean
 * PSA_ERROR_NOT_SUPPORTED instead of proceeding into wolfCrypt and
 * failing later with a less specific error (or, worse, verifying on
 * the default curve of the same size).
 *
 * Each gate is only exercised when the matching flag is absent; in a
 * build with both families compiled in this test is a no-op.
 *
 * Build against the same configuration as the library: compile with
 * -DWOLFSSL_USER_SETTINGS and put the feature shim's include path
 * before the repository root, so HAVE_ECC_KOBLITZ / HAVE_ECC_BRAINPOOL
 * match the libwolfpsa build (the repository root ships its own
 * user_settings.h). The user_settings.h include below makes the
 * flags visible to the case selection.
 */

#include <psa/crypto.h>
#ifdef WOLFSSL_USER_SETTINGS
#include <user_settings.h>
#endif
#include <stdio.h>
#include <string.h>

#define PUB_LEN   65
#define SIG_LEN   64
#define HASH_LEN  32

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

/* A valid 65-byte X9.63 point (the secp256k1 generator); its curve
 * membership is irrelevant - the point of the test is which status the
 * engine reports for a family the build does not support. */
static const uint8_t test_point[PUB_LEN] = {
    0x04,
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb,
    0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8,
    0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4,
    0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48,
    0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10,
    0xd4, 0xb8
};

static void test_unsupported_family(psa_key_type_t pub_type)
{
    psa_status_t status;
    psa_key_attributes_t attrs;
    psa_key_id_t pub = PSA_KEY_ID_NULL;
    uint8_t hash[HASH_LEN];
    uint8_t signature[SIG_LEN];

    memset(hash, 0x2a, sizeof(hash));
    memset(signature, 0x00, sizeof(signature));

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, pub_type);
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    status = psa_import_key(&attrs, test_point, sizeof(test_point), &pub);
    expect(status, PSA_SUCCESS, "import public key (no import gate)");
    if (status != PSA_SUCCESS) {
        return;
    }

    /* The operation must be rejected as not supported by the build,
     * not misinterpreted on the default curve of the same size. */
    status = psa_verify_hash(pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                             sizeof(hash), signature, sizeof(signature));
    expect(status, PSA_ERROR_NOT_SUPPORTED,
           "verify on unsupported family");

    psa_destroy_key(pub);
}

int main(void)
{
    psa_status_t status;

    status = psa_crypto_init();
    expect(status, PSA_SUCCESS, "psa_crypto_init");
    if (status != PSA_SUCCESS) {
        return 1;
    }

#if !defined(HAVE_ECC_KOBLITZ)
    test_unsupported_family(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_K1));
#else
    (void)test_unsupported_family;
#endif
#if !defined(HAVE_ECC_BRAINPOOL)
    test_unsupported_family(
        PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_BRAINPOOL_P_R1));
#else
    (void)test_unsupported_family;
#endif

    if (failures == 0) {
        printf("curve-capability tests: all passed\n");
        return 0;
    }
    printf("curve-capability tests: %d failure(s)\n", failures);
    return 1;
}
