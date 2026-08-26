/* Regression: a raw ECDSA signature whose length differs from
 * the expected r||s width is malformed peer signature data and must be
 * reported as PSA_ERROR_INVALID_SIGNATURE, not
 * PSA_ERROR_INVALID_ARGUMENT, consistent with the later raw-signature
 * conversion failure path in the same function.
 */

#include <psa/crypto.h>
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

int main(void)
{
    psa_status_t status;
    psa_key_attributes_t attrs;
    psa_key_id_t pub = PSA_KEY_ID_NULL;
    /* secp256r1 generator point, X9.63 uncompressed encoding */
    static const uint8_t g_point[PUB_LEN] = {
        0x04,
        0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc,
        0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81,
        0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98,
        0xc2, 0x96,
        0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
        0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57,
        0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf,
        0x51, 0xf5
    };
    uint8_t hash[HASH_LEN];
    uint8_t sig_long[SIG_LEN + 1];

    memset(hash, 0x2a, sizeof(hash));
    memset(sig_long, 0x07, sizeof(sig_long));

    status = psa_crypto_init();
    expect(status, PSA_SUCCESS, "psa_crypto_init");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    attrs = psa_key_attributes_init();
    psa_set_key_type(&attrs,
                     PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    status = psa_import_key(&attrs, g_point, sizeof(g_point), &pub);
    expect(status, PSA_SUCCESS, "import public key");
    if (status != PSA_SUCCESS) {
        return 1;
    }

    /* One byte short: malformed signature, not an API argument error. */
    status = psa_verify_hash(pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                             sizeof(hash), sig_long, SIG_LEN - 1);
    expect(status, PSA_ERROR_INVALID_SIGNATURE,
           "verify with signature one byte short");

    /* One byte long: same. */
    status = psa_verify_hash(pub, PSA_ALG_ECDSA(PSA_ALG_SHA_256), hash,
                             sizeof(hash), sig_long, SIG_LEN + 1);
    expect(status, PSA_ERROR_INVALID_SIGNATURE,
           "verify with signature one byte long");

    psa_destroy_key(pub);

    if (failures == 0) {
        printf("sig-length tests: all passed\n");
        return 0;
    }
    printf("sig-length tests: %d failure(s)\n", failures);
    return 1;
}
