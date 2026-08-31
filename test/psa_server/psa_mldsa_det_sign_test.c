/* Regression: DeterministicHashML-DSA must sign deterministically.
 *
 * The input_is_hash dispatch tested PSA_ALG_IS_HASH_ML_DSA first, which is
 * true for both the hedged and the deterministic family (the predicate
 * masks off the family selector bit), so deterministic requests were
 * handled by the hedged branch (fresh RNG) and the deterministic branch
 * was unreachable. Signing the same digest twice produced different
 * signatures.
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

int main(void)
{
    psa_status_t status;
    psa_key_attributes_t attrs;
    psa_key_id_t key = PSA_KEY_ID_NULL;
    psa_algorithm_t alg;
    uint8_t digest[HASH_LEN];
    uint8_t sig1[SIG_MAX];
    uint8_t sig2[SIG_MAX];
    size_t sig1_len = 0;
    size_t sig2_len = 0;

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    alg = PSA_ALG_DETERMINISTIC_HASH_ML_DSA(PSA_ALG_SHA_256);
    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ML_DSA_KEY_PAIR);
    psa_set_key_bits(&attrs, 128);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, alg);
    status = psa_generate_key(&attrs, &key);
    if (status != PSA_SUCCESS) {
        /* ML-DSA not built into the library. */
        printf("det-sign tests: skipped (generate: 0x%08x)\n",
               (unsigned)status);
        return 0;
    }

    memset(digest, 0x42, sizeof(digest));

    status = psa_sign_hash(key, alg, digest, sizeof(digest),
                           sig1, sizeof(sig1), &sig1_len);
    expect(status, PSA_SUCCESS, "first deterministic sign");
    if (status != PSA_SUCCESS) {
        return 1;
    }
    status = psa_sign_hash(key, alg, digest, sizeof(digest),
                           sig2, sizeof(sig2), &sig2_len);
    expect(status, PSA_SUCCESS, "second deterministic sign");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    /* The determinism contract: same key, same digest, same algorithm
     * must yield byte-identical signatures. */
    if (sig1_len != sig2_len || memcmp(sig1, sig2, sig1_len) != 0) {
        printf("FAIL: deterministic signatures differ (len %zu vs %zu)\n",
               sig1_len, sig2_len);
        failures++;
    }

    status = psa_verify_hash(key, alg, digest, sizeof(digest),
                             sig1, sig1_len);
    expect(status, PSA_SUCCESS, "verify deterministic signature");

    if (failures == 0) {
        printf("det-sign tests: all passed\n");
        return 0;
    }
    printf("det-sign tests: %d failure(s)\n", failures);
    return 1;
}
