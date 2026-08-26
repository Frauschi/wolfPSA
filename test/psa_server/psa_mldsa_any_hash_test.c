/* Regression: the HashML-DSA ANY_HASH policy wildcard must not
 * cross the hedged/deterministic family boundary.
 *
 * The first wildcard block matched with PSA_ALG_IS_HASH_ML_DSA, which is
 * true for both families (the mask ~0x1ff covers the family selector
 * bit), so a hedged-wildcard policy accepted deterministic requests and
 * vice versa, and the deterministic block below it was unreachable.
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

#define HASH_LEN  32
#define SIG_MAX   4096

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

static psa_status_t make_key(psa_key_id_t *key, psa_algorithm_t policy_alg)
{
    psa_key_attributes_t attrs;

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, policy_alg);
    *key = PSA_KEY_ID_NULL;
    return psa_generate_key(&attrs, key);
}

static void sign_case(psa_key_id_t key, psa_algorithm_t request_alg,
                      psa_status_t want, const char *what)
{
    uint8_t digest[HASH_LEN];
    uint8_t sig[SIG_MAX];
    size_t sig_len = 0;

    memset(digest, 0x7e, sizeof(digest));
    expect(psa_sign_hash(key, request_alg, digest, sizeof(digest),
                         sig, sizeof(sig), &sig_len),
           want, what);
}

int main(void)
{
    psa_status_t status;
    psa_key_id_t hedged_key = PSA_KEY_ID_NULL;
    psa_key_id_t det_key = PSA_KEY_ID_NULL;
    psa_algorithm_t hedged;
    psa_algorithm_t det;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    hedged = PSA_ALG_HASH_ML_DSA(PSA_ALG_ANY_HASH);
    det = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_ANY_HASH);
    status = make_key(&hedged_key, hedged);
    if (status != PSA_SUCCESS) {
        /* ML-DSA not built into the library. */
        printf("any-hash tests: skipped (generate: 0x%08x)\n",
               (unsigned)status);
        return 0;
    }
    status = make_key(&det_key, det);
    if (status != PSA_SUCCESS) {
        return 1;
    }

    /* Hedged wildcard policy: accepts hedged, rejects deterministic. */
    sign_case(hedged_key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256),
              PSA_SUCCESS, "hedged policy + hedged request");
    sign_case(hedged_key,
              PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256),
              PSA_ERROR_NOT_PERMITTED,
              "hedged policy + deterministic request");

    /* Deterministic wildcard policy: accepts deterministic, rejects
     * hedged. */
    sign_case(det_key, PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256),
              PSA_SUCCESS, "deterministic policy + deterministic request");
    sign_case(det_key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256),
              PSA_ERROR_NOT_PERMITTED,
              "deterministic policy + hedged request");

    if (failures == 0) {
        printf("any-hash tests: all passed\n");
        return 0;
    }
    printf("any-hash tests: %d failure(s)\n", failures);
    return 1;
}
