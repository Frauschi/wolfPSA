/* Regression: PBKDF2-AES-CMAC-PRF-128 must follow RFC 4615
 * step 1 for 128-bit keys.
 *
 * RFC 4615 section 3: if the variable-length key is exactly 16 octets
 * it is used directly as the AES-CMAC key; otherwise the CMAC key is
 * CMAC(0^128, key). The implementation always took the normalization
 * branch, so a 16-byte password produced a PRF key (and therefore a
 * derived key) that no RFC 4615-conformant implementation agrees
 * with.
 *
 * The expected values come from an independent reference
 * implementation of RFC 4615 over the same AES-CMAC primitive:
 *  - case A uses a 16-byte password (direct key, the flagged branch);
 *  - cases B and C use non-16-byte passwords (normalization branch,
 *    which must keep working).
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

static int failures;
static int skipped;

static void expect_bytes(const uint8_t *got, size_t got_len,
                         const uint8_t *want, size_t want_len,
                         const char *what)
{
    if (got_len != want_len ||
        (got_len > 0 && memcmp(got, want, got_len) != 0)) {
        size_t i;
        printf("FAIL: %s\n", what);
        for (i = 0; i < (got_len < want_len ? got_len : want_len); i++)
            printf("  %02x", got[i]);
        printf("\n");
        failures++;
    }
}

static int run_case(const uint8_t *password, size_t password_length,
                    const uint8_t *salt, size_t salt_length, uint32_t cost,
                    const uint8_t *expected, size_t expected_length,
                    const char *name)
{
    psa_key_derivation_operation_t op;
    psa_status_t status;
    uint8_t dk[64];

    op = psa_key_derivation_operation_init();

    status = psa_key_derivation_setup(&op, PSA_ALG_PBKDF2_AES_CMAC_PRF_128);
    if (status != PSA_SUCCESS) {
        printf("SKIP: %s setup: 0x%08x\n", name, (unsigned)status);
        skipped++;
        return 0;
    }

    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_PASSWORD, password, password_length);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_length);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_integer(&op,
                                                  PSA_KEY_DERIVATION_INPUT_COST,
                                                  cost);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(&op, dk, expected_length);

    psa_key_derivation_abort(&op);

    if (status != PSA_SUCCESS) {
        printf("FAIL: %s: status 0x%08x\n", name, (unsigned)status);
        failures++;
        return 0;
    }

    expect_bytes(dk, expected_length, expected, expected_length, name);
    return 0;
}

int main(void)
{
    /* 16-byte password: RFC 4615 uses it directly as the CMAC key. */
    static const uint8_t pwA[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t dkA[] = {
        0xd7, 0x24, 0xea, 0x6c, 0xe8, 0xe3, 0x97, 0x98,
        0x7b, 0xc5, 0x60, 0x0f, 0xc9, 0x63, 0x89, 0x28,
        0xec, 0xdf, 0x2b, 0x28, 0x08, 0x7d, 0x1f, 0xd2,
        0xe6, 0x1d, 0x23, 0xd6
    };

    /* 6-byte password: normalization branch. */
    static const uint8_t pwB[] = {
        'p', 'a', 's', 's', 'w', 'd'
    };
    static const uint8_t dkB[] = {
        0x8c, 0x8f, 0xb9, 0xc6, 0x2a, 0x18, 0x50, 0x55,
        0x14, 0x5d, 0xad, 0xe2, 0x3e, 0x71, 0xde, 0xcb,
        0x9a, 0x41, 0xcf, 0x27, 0xb2, 0x60, 0xcd, 0xe6,
        0xb0, 0xd8, 0x37, 0xc0
    };

    /* 21-byte password, cost 3, single-block output. */
    static const uint8_t pwC[] = {
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25
    };
    static const uint8_t dkC[] = {
        0x58, 0x04, 0x00, 0x48, 0x41, 0x83, 0x13, 0x3e,
        0x70, 0xaa, 0x63, 0xf6, 0xe7, 0x7a, 0x9f, 0x83
    };

    static const uint8_t salt4[] = { 's', 'a', 'l', 't' };
    static const uint8_t saltC[] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
    };

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed\n");
        return 0;
    }

    run_case(pwA, sizeof(pwA), salt4, sizeof(salt4), 2, dkA, sizeof(dkA),
             "16-byte password (direct key)");
    run_case(pwB, sizeof(pwB), salt4, sizeof(salt4), 2, dkB, sizeof(dkB),
             "6-byte password (normalized key)");
    run_case(pwC, sizeof(pwC), saltC, sizeof(saltC), 3, dkC, sizeof(dkC),
             "21-byte password cost 3");

    if (failures == 0) {
        printf("pbkdf2-cmac tests: all passed (%d skipped)\n", skipped);
        return 0;
    }
    printf("pbkdf2-cmac tests: %d failure(s), %d skipped\n",
           failures, skipped);
    return 1;
}
