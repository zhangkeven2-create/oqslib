// SPDX-License-Identifier: MIT

#include "speed_profile_bench.h"

#include <stdio.h>
#include <string.h>

#include "ds_benchmark.h"

typedef struct {
        uint64_t iterations;
        uint64_t sections[SPEED_PROFILE_SECTION_COUNT];
} speed_profile_accumulator;

static void speed_profile_accumulator_init(speed_profile_accumulator *acc) {
        memset(acc, 0, sizeof(*acc));
}

static void speed_profile_accumulator_update(speed_profile_accumulator *acc,
                                             const speed_profile_iteration_totals *totals) {
        if (acc == NULL || totals == NULL) {
                return;
        }
        acc->iterations++;
        for (size_t i = 0; i < SPEED_PROFILE_SECTION_COUNT; i++) {
                acc->sections[i] += totals->sections[i];
        }
}

static double ns_to_us(uint64_t ns) {
        return (double) ns / 1000.0;
}

static void speed_profile_print_adjustments(speed_profile_mask_t mask,
                                            const speed_profile_accumulator *acc,
                                            double base_mean_us) {
        if (mask == SPEED_PROFILE_KIND_NONE || acc == NULL || acc->iterations == 0) {
                return;
        }

        double ntt_intt_us = 0.0;
        if (mask & SPEED_PROFILE_KIND_MLKEM) {
                uint64_t total = acc->sections[SPEED_PROFILE_SECTION_MLKEM_NTT] +
                                 acc->sections[SPEED_PROFILE_SECTION_MLKEM_INTT];
                ntt_intt_us = ns_to_us(total) / (double) acc->iterations;
        } else if (mask & SPEED_PROFILE_KIND_MLDSA) {
                uint64_t total = acc->sections[SPEED_PROFILE_SECTION_MLDSA_NTT] +
                                 acc->sections[SPEED_PROFILE_SECTION_MLDSA_INTT];
                ntt_intt_us = ns_to_us(total) / (double) acc->iterations;
        }

        double sha3_us = ns_to_us(acc->sections[SPEED_PROFILE_SECTION_SHA3]) /
                         (double) acc->iterations;

        double excl_ntt = base_mean_us - ntt_intt_us;
        if (excl_ntt < 0) {
                excl_ntt = 0;
        }
        double excl_all = excl_ntt - sha3_us;
        if (excl_all < 0) {
                excl_all = 0;
        }

        printf("   -> mean(us) excl NTT+INTT: %.3f\n", excl_ntt);
        printf("   -> mean(us) excl NTT+INTT+SHA3: %.3f\n", excl_all);
}

OQS_STATUS speed_profile_run_benchmark(const char *label,
                                       uint64_t duration,
                                       speed_profile_mask_t mask,
                                       speed_profile_operation op,
                                       void *ctx) {
        if (op == NULL || label == NULL) {
                return OQS_ERROR;
        }

        speed_profile_iteration_totals iteration_totals;
        speed_profile_accumulator accumulator;
        speed_profile_accumulator_init(&accumulator);

        DEFINE_TIMER_VARIABLES
        INITIALIZE_TIMER
        uint64_t bench_time_goal_usecs = 1000000 * duration;

        while (_bench_time_cumulative < bench_time_goal_usecs) {
                speed_profile_iteration_begin(mask);
                START_TIMER {
                        OQS_STATUS status = op(ctx);
                        if (status != OQS_SUCCESS) {
                                speed_profile_iteration_end(NULL);
                                return status;
                        }
                }
                STOP_TIMER
                speed_profile_iteration_end(&iteration_totals);
                speed_profile_accumulator_update(&accumulator, &iteration_totals);
        }

        FINALIZE_TIMER
        PRINT_TIMER_AVG(label);
        speed_profile_print_adjustments(mask, &accumulator, _bench_time_mean);
        return OQS_SUCCESS;
}
