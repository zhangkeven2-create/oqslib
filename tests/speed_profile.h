// SPDX-License-Identifier: MIT

#ifndef TESTS_SPEED_PROFILE_H
#define TESTS_SPEED_PROFILE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t speed_profile_mask_t;

#define SPEED_PROFILE_KIND_NONE   ((speed_profile_mask_t)0u)
#define SPEED_PROFILE_KIND_MLKEM  ((speed_profile_mask_t)1u << 0)
#define SPEED_PROFILE_KIND_MLDSA  ((speed_profile_mask_t)1u << 1)
#define SPEED_PROFILE_KIND_ALL    (SPEED_PROFILE_KIND_MLKEM | SPEED_PROFILE_KIND_MLDSA)

typedef enum {
        SPEED_PROFILE_SECTION_MLKEM_NTT = 0,
        SPEED_PROFILE_SECTION_MLKEM_INTT,
        SPEED_PROFILE_SECTION_MLDSA_NTT,
        SPEED_PROFILE_SECTION_MLDSA_INTT,
        SPEED_PROFILE_SECTION_SHA3,
        SPEED_PROFILE_SECTION_COUNT
} speed_profile_section_t;

typedef struct {
        uint64_t sections[SPEED_PROFILE_SECTION_COUNT];
} speed_profile_iteration_totals;

void speed_profile_iteration_begin(speed_profile_mask_t mask);
void speed_profile_iteration_end(speed_profile_iteration_totals *out);
void speed_profile_section_enter(speed_profile_mask_t required_mask, speed_profile_section_t section);
void speed_profile_section_leave(speed_profile_mask_t required_mask, speed_profile_section_t section);

#ifdef __cplusplus
}
#endif

#endif
