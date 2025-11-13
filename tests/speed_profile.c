// SPDX-License-Identifier: MIT

#include "speed_profile.h"

#include <stddef.h>
#include <string.h>
#include <time.h>

typedef struct {
        uint64_t start_ns;
        unsigned depth;
} speed_profile_section_state;

static speed_profile_mask_t current_mask = SPEED_PROFILE_KIND_NONE;
static speed_profile_iteration_totals current_totals;
static speed_profile_section_state section_states[SPEED_PROFILE_SECTION_COUNT];

static uint64_t speed_profile_now_ns(void) {
        struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
        clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
        clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
        return (uint64_t) ts.tv_sec * 1000000000ULL + (uint64_t) ts.tv_nsec;
}

void speed_profile_iteration_begin(speed_profile_mask_t mask) {
        current_mask = mask;
        memset(&current_totals, 0, sizeof(current_totals));
        memset(section_states, 0, sizeof(section_states));
}

void speed_profile_iteration_end(speed_profile_iteration_totals *out) {
        if (out != NULL) {
                *out = current_totals;
        }
        current_mask = SPEED_PROFILE_KIND_NONE;
        memset(&current_totals, 0, sizeof(current_totals));
        memset(section_states, 0, sizeof(section_states));
}

static int speed_profile_section_enabled(speed_profile_mask_t required_mask) {
        if (required_mask == SPEED_PROFILE_KIND_NONE) {
            return 0;
        }
        return (current_mask & required_mask) != 0;
}

void speed_profile_section_enter(speed_profile_mask_t required_mask, speed_profile_section_t section) {
        if (!speed_profile_section_enabled(required_mask)) {
                return;
        }
        speed_profile_section_state *state = &section_states[section];
        state->depth++;
        if (state->depth == 1) {
                state->start_ns = speed_profile_now_ns();
        }
}

void speed_profile_section_leave(speed_profile_mask_t required_mask, speed_profile_section_t section) {
        if (!speed_profile_section_enabled(required_mask)) {
                return;
        }
        speed_profile_section_state *state = &section_states[section];
        if (state->depth == 0) {
                return;
        }
        state->depth--;
        if (state->depth == 0) {
                uint64_t end_ns = speed_profile_now_ns();
                current_totals.sections[section] += end_ns - state->start_ns;
                state->start_ns = 0;
        }
}
