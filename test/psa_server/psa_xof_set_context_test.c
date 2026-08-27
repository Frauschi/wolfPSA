/* Regression: a rejected XOF context must abort the
 * operation.
 *
 * psa_xof_set_context() returns PSA_ERROR_INVALID_ARGUMENT for
 * SHAKE (no context field), but it returned the status directly,
 * leaving the operation active: psa_xof_update() on the same
 * operation still succeeded after the failed set_context, where the
 * multipart contract expects an error to put the operation into the
 * inactive state (consistent with every other error path in
 * psa_xof.c, which aborts via wolfpsa_xof_fail).
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <string.h>

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
    psa_xof_operation_t op;
    uint8_t context[4];
    uint8_t input[8];
    uint8_t output[16];

    op = psa_xof_operation_init();
    memset(context, 0x5a, sizeof(context));
    memset(input, 0x11, sizeof(input));

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    /* NULL operation: plain INVALID_ARGUMENT, nothing to abort. */
    expect(psa_xof_set_context(NULL, context, sizeof(context)),
           PSA_ERROR_INVALID_ARGUMENT, "set_context with NULL op");

    /* Runtime backend detection (one binary, both configs): a
     * SHAKE-less build returns NOT_SUPPORTED from setup, in which
     * case the stubbed no-backend error paths are exercised. */
    status = psa_xof_setup(&op, PSA_ALG_SHAKE128);
    if (status == PSA_SUCCESS) {
        /* Active operation: the rejected context must abort it. */
        status = psa_xof_set_context(&op, context, sizeof(context));
        expect(status, PSA_ERROR_INVALID_ARGUMENT,
               "set_context rejected");

        expect(psa_xof_update(&op, input, sizeof(input)),
               PSA_ERROR_BAD_STATE, "update after rejected set_context");
        expect(psa_xof_output(&op, output, sizeof(output)),
               PSA_ERROR_BAD_STATE, "output after rejected set_context");
        expect(psa_xof_abort(&op), PSA_SUCCESS, "abort (idempotent)");
    } else {
        expect(status, PSA_ERROR_NOT_SUPPORTED, "setup (no backend)");
        expect(psa_xof_set_context(&op, context, sizeof(context)),
               PSA_ERROR_BAD_STATE, "set_context on stub op");
        expect(psa_xof_update(&op, input, sizeof(input)),
               PSA_ERROR_BAD_STATE, "update on stub op");
        expect(psa_xof_abort(&op), PSA_SUCCESS, "abort (stub)");
    }

    /* An operation with no context must also report BAD_STATE. */
    op = psa_xof_operation_init();
    expect(psa_xof_set_context(&op, context, sizeof(context)),
           PSA_ERROR_BAD_STATE, "set_context on inactive op");

    if (failures == 0) {
        printf("set-context tests: all passed\n");
        return 0;
    }
    printf("set-context tests: %d failure(s)\n", failures);
    return 1;
}
