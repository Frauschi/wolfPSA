/* Regression: SP800-108 label/context lengths must not
 * truncate to word32.
 *
 * Both SP800-108 backends passed ctx->label_length and
 * ctx->context_length to wc_HmacUpdate/wc_CmacUpdate with a direct
 * (word32) cast; a 64-bit length of UINT32_MAX+1 bytes truncated to
 * zero (the derivation silently continued with an empty label or
 * context) and other oversized lengths used only the low 32 bits.
 *
 * A label or context of UINT32_MAX+1 bytes must be rejected with
 * PSA_ERROR_INVALID_ARGUMENT. The happy path with small inputs must
 * keep deriving successfully.
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BIG_LEN  ((size_t)UINT32_MAX + 1u)

static int failures;

static int expect_status(const char *label, psa_status_t status,
                         psa_status_t expected)
{
    if (status != expected) {
        printf("FAIL %s: status 0x%08x want 0x%08x\n", label,
               (unsigned)status, (unsigned)expected);
        return 1;
    }
    return 0;
}

/* Classify an oversized-input derivation. The oversized label or
 * context is copied into the operation inside the library before the
 * length check runs, so a machine that cannot hold the two 4 GiB test
 * buffers plus that copy gets PSA_ERROR_INSUFFICIENT_MEMORY from the
 * copy and must skip, not fail.
 *
 * Returns 0 when rejected as expected, 1 when the run must skip, 2 on
 * any other status (a real failure). */
static int check_rejected(const char *label, psa_status_t status)
{
    if (status == PSA_ERROR_INVALID_ARGUMENT) {
        return 0;
    }
    if (status == PSA_ERROR_INSUFFICIENT_MEMORY) {
        printf("SKIP: %s: library out of memory\n", label);
        return 1;
    }
    printf("FAIL %s: status 0x%08x want 0x%08x\n", label,
           (unsigned)status, (unsigned)PSA_ERROR_INVALID_ARGUMENT);
    return 2;
}

static uint8_t *alloc_big(const char *what)
{
    uint8_t *p = (uint8_t *)malloc(BIG_LEN);

    if (p == NULL) {
        printf("SKIP: %s allocation failed\n", what);
    }
    else {
        memset(p, 0x5a, BIG_LEN);
    }
    return p;
}

/* SP800-108 derivation returning only the status of the final
 * output call; the big buffer selects which field gets the
 * oversized value (big_label / big_context), NULL means small. */
static psa_status_t derive_hmac(const uint8_t *big_label,
                                const uint8_t *big_context,
                                uint8_t *dk)
{
    static const uint8_t secret[20];
    static const uint8_t small[4] = { 1, 2, 3, 4 };
    psa_key_derivation_operation_t op;
    psa_status_t status;

    op = psa_key_derivation_operation_init();
    status = psa_key_derivation_setup(&op,
                                      PSA_ALG_SP800_108_COUNTER_HMAC(
                                          PSA_ALG_SHA_256));
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, secret, sizeof(secret));
    if (status == PSA_SUCCESS) {
        const uint8_t *label = (big_label != NULL) ? big_label : small;
        size_t label_len = (big_label != NULL) ? BIG_LEN : sizeof(small);

        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_LABEL, label, label_len);
    }
    if (status == PSA_SUCCESS) {
        const uint8_t *context = (big_context != NULL) ? big_context : small;
        size_t context_len =
            (big_context != NULL) ? BIG_LEN : sizeof(small);

        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len);
    }
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(&op, dk, 16);

    psa_key_derivation_abort(&op);
    return status;
}

static psa_status_t derive_cmac(const uint8_t *big_context, uint8_t *dk)
{
    static const uint8_t aes_key[16];
    static const uint8_t small[4] = { 1, 2, 3, 4 };
    psa_key_derivation_operation_t op;
    psa_status_t status;

    op = psa_key_derivation_operation_init();
    status = psa_key_derivation_setup(&op, PSA_ALG_SP800_108_COUNTER_CMAC);
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SECRET, aes_key, sizeof(aes_key));
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_LABEL, small, sizeof(small));
    if (status == PSA_SUCCESS) {
        const uint8_t *context =
            (big_context != NULL) ? big_context : small;
        size_t context_len =
            (big_context != NULL) ? BIG_LEN : sizeof(small);

        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_CONTEXT, context, context_len);
    }
    if (status == PSA_SUCCESS)
        status = psa_key_derivation_output_bytes(&op, dk, 16);

    psa_key_derivation_abort(&op);
    return status;
}

int main(void)
{
    uint8_t dk[16];
    uint8_t *big_label;
    uint8_t *big_context;
    int skipped = 0;

    if (psa_crypto_init() != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed\n");
        return 0;
    }

    big_label = alloc_big("big label");
    big_context = alloc_big("big context");
    if (big_label == NULL || big_context == NULL)
        skipped++;

    if (skipped == 0) {
        int rc;

        rc = check_rejected("HMAC oversized label",
                            derive_hmac(big_label, NULL, dk));
        if (rc == 1) {
            skipped = 1;
        }
        else if (rc == 2) {
            failures++;
        }
        if (skipped == 0) {
            rc = check_rejected("HMAC oversized context",
                                derive_hmac(NULL, big_context, dk));
            if (rc == 1) {
                skipped = 1;
            }
            else if (rc == 2) {
                failures++;
            }
        }
        if (skipped == 0) {
            rc = check_rejected("CMAC oversized context",
                                derive_cmac(big_context, dk));
            if (rc == 1) {
                skipped = 1;
            }
            else if (rc == 2) {
                failures++;
            }
        }
    }
    if (skipped != 0) {
        printf("length-check tests: skipped (out of memory)\n");
        free(big_label);
        free(big_context);
        return 0;
    }
    free(big_label);
    free(big_context);

    if (expect_status("HMAC small inputs", derive_hmac(NULL, NULL, dk),
                      PSA_SUCCESS) != 0)
        failures++;
    if (expect_status("CMAC small inputs", derive_cmac(NULL, dk),
                      PSA_SUCCESS) != 0)
        failures++;

    if (failures == 0) {
        printf("length-check tests: all passed\n");
        return 0;
    }
    printf("length-check tests: %d failure(s)\n", failures);
    return 1;
}
