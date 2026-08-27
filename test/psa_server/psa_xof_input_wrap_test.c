/* Regression: XOF input accumulation must not wrap the 32-bit
 * buffer sizing.
 *
 * psa_xof_update() sized the accumulation buffer as
 * ibuf_len + (word32)input_length, which wraps modulo 2^32: after a
 * 2 GiB update, a second update of 2 GiB + 256 bytes computed a
 * required capacity of 256, skipped the growth, and copied ~2 GiB
 * past the end of the allocation.  The doubling loop in
 * psa_xof_ibuf_grow() could also wrap to zero and spin forever.
 *
 * The fix sizes in size_t and rejects a combined input above
 * UINT32_MAX (the backend Absorb() takes word32 lengths), so the
 * second update must be rejected cleanly instead of overflowing.
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define U1_LEN  ((size_t)0x80000000u)          /* 2 GiB */
#define U2_LEN  ((size_t)0x80000000u + 256u)   /* 2 GiB + 256 */

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
    uint8_t *in1;
    uint8_t *in2;

    op = psa_xof_operation_init();

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    in1 = (uint8_t *)malloc(U1_LEN);
    in2 = (uint8_t *)malloc(U2_LEN);
    if (in1 == NULL || in2 == NULL) {
        printf("ibuf-wrap tests: skipped (out of memory)\n");
        free(in1);
        free(in2);
        return 0;
    }
    memset(in1, 0x11, U1_LEN);
    memset(in2, 0x22, U2_LEN);

    status = psa_xof_setup(&op, PSA_ALG_SHAKE128);
    expect(status, PSA_SUCCESS, "setup");

    status = psa_xof_update(&op, in1, U1_LEN);
    if (status == PSA_ERROR_INSUFFICIENT_MEMORY) {
        /* The update copies the input into the operation's own buffer;
         * without room for it on top of the two test buffers, skip. */
        printf("ibuf-wrap tests: skipped (out of memory)\n");
        free(in1);
        free(in2);
        psa_xof_abort(&op);
        return 0;
    }
    expect(status, PSA_SUCCESS, "first update (2 GiB)");

    /* Combined length 0x100000100 wraps the word32 sizing: must be
     * rejected, never copied. */
    status = psa_xof_update(&op, in2, U2_LEN);
    expect(status, PSA_ERROR_INVALID_ARGUMENT,
           "second update (total past 2^32)");

    free(in1);
    free(in2);
    psa_xof_abort(&op);

    if (failures == 0) {
        printf("ibuf-wrap tests: all passed\n");
        return 0;
    }
    printf("ibuf-wrap tests: %d failure(s)\n", failures);
    return 1;
}
