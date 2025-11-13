// SPDX-License-Identifier: MIT

#ifndef TESTS_SPEED_PROFILE_BENCH_H
#define TESTS_SPEED_PROFILE_BENCH_H

#include <oqs/oqs.h>

#include "speed_profile.h"

typedef OQS_STATUS (*speed_profile_operation)(void *ctx);

OQS_STATUS speed_profile_run_benchmark(const char *label,
                                       uint64_t duration,
                                       speed_profile_mask_t mask,
                                       speed_profile_operation op,
                                       void *ctx);

#endif
