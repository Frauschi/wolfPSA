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

static void verify_case(psa_key_id_t key, psa_algorithm_t request_alg,
                        const uint8_t *digest, const uint8_t *sig,
                        size_t sig_len, psa_status_t want, const char *what)
{
    expect(psa_verify_hash(key, request_alg, digest, HASH_LEN, sig,
                           sig_len),
           want, what);
}

int main(void)
{
    psa_status_t status;
    psa_key_id_t hedged_key = PSA_KEY_ID_NULL;
    psa_key_id_t det_key = PSA_KEY_ID_NULL;
    psa_key_id_t concrete_key = PSA_KEY_ID_NULL;
    psa_algorithm_t hedged;
    psa_algorithm_t det;
    uint8_t digest[HASH_LEN];
    uint8_t hedged_sig[SIG_MAX];
    size_t hedged_sig_len = 0;
    uint8_t det_sig[SIG_MAX];
    size_t det_sig_len = 0;

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
    status = make_key(&concrete_key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256));
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

    /* Verification is family-independent (FIPS 204: both families
     * dispatch to the same VerifyCtxHash), so a key with a wildcard
     * policy of one family admits a verify request from the other
     * family. Pre-fix the policy check returned NOT_PERMITTED for the
     * wildcard policy that the pre-PR mask used to admit. */
    memset(digest, 0x7e, sizeof(digest));
    expect(psa_sign_hash(hedged_key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256),
                         digest, HASH_LEN, hedged_sig, SIG_MAX,
                         &hedged_sig_len),
           PSA_SUCCESS, "sign digest with hedged key");
    expect(psa_sign_hash(det_key,
                         PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256),
                         digest, HASH_LEN, det_sig, SIG_MAX, &det_sig_len),
           PSA_SUCCESS, "sign digest with deterministic key");

    verify_case(hedged_key,
                PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256), digest,
                hedged_sig, hedged_sig_len, PSA_SUCCESS,
                "hedged wildcard policy + deterministic verify request");
    verify_case(det_key, PSA_ALG_HASH_ML_DSA(PSA_ALG_SHA_256), digest,
                det_sig, det_sig_len, PSA_SUCCESS,
                "deterministic wildcard policy + hedged verify request");

    /* The verify equivalence must not loosen the hash match: a
     * concrete policy still rejects a different hash, even across
     * families. */
    verify_case(concrete_key,
                PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_384), digest,
                det_sig, det_sig_len, PSA_ERROR_NOT_PERMITTED,
                "concrete policy + cross-family different-hash request");

    if (failures == 0) {
        printf("any-hash tests: all passed\n");
        return 0;
    }
    printf("any-hash tests: %d failure(s)\n", failures);
    return 1;
}
