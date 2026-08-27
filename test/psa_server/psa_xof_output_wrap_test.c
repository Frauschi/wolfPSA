/* Regression: XOF output accounting must not wrap at 2^32.
 *
 * psa_xof_output() computed the squeezed byte count as
 * n_blocks * block_size in word32; for a request of 4294967376
 * bytes (25565282 full 168-byte SHAKE128 blocks) the product wrapped
 * to 80, so the accounting pointer advanced 80 bytes while the
 * backend had written the full 4 GiB, and the next squeeze started
 * 4 GiB short of where it should have, corrupting the output
 * (segments of the stream landed out of order).
 *
 * A single large output request must yield exactly the same bytes
 * as the same total served in sub-2^32 chunks.
 */

#include <psa/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 2^32 + 80 = 25565282 full 168-byte blocks (SHAKE128 rate). */
#define R_LEN   ((size_t)4294967376u)
#define HALF    (R_LEN / 2u)

static int failures;

static void expect(psa_status_t got, psa_status_t want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s: got 0x%08x want 0x%08x\n",
               what, (unsigned)got, (unsigned)want);
        failures++;
    }
}

/* This test commits two R_LEN buffers. Under Linux overcommit,
 * malloc() succeeds even when the machine cannot back the pages,
 * so the NULL-skip path never fires and the kernel OOM killer takes
 * the process out instead. When MemAvailable can be read, require
 * the peak plus a 1 GiB headroom; otherwise fall back to the
 * malloc-failure skip. */
static int mem_budget_ok(size_t peak)
{
#ifdef __linux__
    long long need = (long long)peak + (1LL << 30);
    FILE *f = fopen("/proc/meminfo", "r");
    long long avail_kb = -1;
    char line[128];

    if (f != NULL) {
        while (fgets(line, sizeof(line), f) != NULL) {
            long long kb;

            if (sscanf(line, "MemAvailable: %lld", &kb) == 1) {
                avail_kb = kb;
                break;
            }
        }
        fclose(f);
    }
    if (avail_kb >= 0) {
        return avail_kb * 1024LL >= need;
    }
#endif
    (void)peak;
    return 1;
}

int main(void)
{
    psa_status_t status;
    psa_xof_operation_t opA;
    psa_xof_operation_t opB;
    uint8_t input[16];
    uint8_t *bufA;
    uint8_t *bufB;
    size_t i;

    opA = psa_xof_operation_init();
    opB = psa_xof_operation_init();
    memset(input, 0x9c, sizeof(input));

    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        printf("SKIP: psa_crypto_init failed: 0x%08x\n", (unsigned)status);
        return 0;
    }

    if (!mem_budget_ok(2 * R_LEN)) {
        printf("output-wrap tests: skipped (insufficient memory)\n");
        return 0;
    }

    bufA = (uint8_t *)malloc(R_LEN);
    bufB = (uint8_t *)malloc(R_LEN);
    if (bufA == NULL || bufB == NULL) {
        printf("output-wrap tests: skipped (out of memory)\n");
        free(bufA);
        free(bufB);
        return 0;
    }

    /* Operation A: one request for the full amount. */
    status = psa_xof_setup(&opA, PSA_ALG_SHAKE128);
    expect(status, PSA_SUCCESS, "setup A");
    status = psa_xof_update(&opA, input, sizeof(input));
    expect(status, PSA_SUCCESS, "update A");
    status = psa_xof_output(&opA, bufA, R_LEN);
    expect(status, PSA_SUCCESS, "output A (single 4 GiB request)");

    /* Operation B: the same total in two sub-2^32 requests. */
    status = psa_xof_setup(&opB, PSA_ALG_SHAKE128);
    expect(status, PSA_SUCCESS, "setup B");
    status = psa_xof_update(&opB, input, sizeof(input));
    expect(status, PSA_SUCCESS, "update B");
    status = psa_xof_output(&opB, bufB, HALF);
    expect(status, PSA_SUCCESS, "output B first half");
    status = psa_xof_output(&opB, bufB + HALF, HALF);
    expect(status, PSA_SUCCESS, "output B second half");

    /* Same input, same total: the bytes must be identical. */
    for (i = 0; i < R_LEN; i += 4096u) {
        size_t n = (R_LEN - i < 4096u) ? R_LEN - i : 4096u;

        if (memcmp(bufA + i, bufB + i, n) != 0) {
            printf("FAIL: output differs from chunked reference at "
                   "offset %llu\n", (unsigned long long)i);
            failures++;
            break;
        }
    }

    free(bufA);
    free(bufB);
    psa_xof_abort(&opA);
    psa_xof_abort(&opB);

    if (failures == 0) {
        printf("output-wrap tests: all passed\n");
        return 0;
    }
    printf("output-wrap tests: %d failure(s)\n", failures);
    return 1;
}
