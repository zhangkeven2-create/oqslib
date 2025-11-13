// SPDX-License-Identifier: MIT

#include "speed_profile.h"

#include <oqs/sha3.h>
#include <stddef.h>

#define DECLARE_SPEED_WRAP(symbol, mask, section)          \
        void __real_##symbol(void *arg);                   \
        void __wrap_##symbol(void *arg) {                  \
                speed_profile_section_enter(mask, section);\
                __real_##symbol(arg);                      \
                speed_profile_section_leave(mask, section);\
        }

#if defined(SPEED_WRAPPERS_ENABLE_MLKEM)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM512_C_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM512_X86_64_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM768_C_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM768_X86_64_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM1024_C_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM1024_X86_64_poly_ntt, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_NTT)

DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM512_C_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM512_X86_64_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM768_C_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM768_X86_64_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM1024_C_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
DECLARE_SPEED_WRAP(PQCP_MLKEM_NATIVE_MLKEM1024_X86_64_poly_invntt_tomont, SPEED_PROFILE_KIND_MLKEM, SPEED_PROFILE_SECTION_MLKEM_INTT)
#endif

#if defined(SPEED_WRAPPERS_ENABLE_MLDSA)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_44_ref_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_44_avx2_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_65_ref_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_65_avx2_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_87_ref_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_87_avx2_poly_ntt, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_NTT)

DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_44_ref_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_44_ref_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_44_avx2_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_65_ref_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_65_ref_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_65_avx2_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_87_ref_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_87_ref_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
DECLARE_SPEED_WRAP(pqcrystals_ml_dsa_87_avx2_poly_invntt_tomont, SPEED_PROFILE_KIND_MLDSA, SPEED_PROFILE_SECTION_MLDSA_INTT)
#endif

void __real_OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen);
void __real_OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state);
void __real_OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen);
void __real_OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state);
void __real_OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state);
void __real_OQS_SHA3_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx *state);
void __real_OQS_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src);

void __real_OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen);
void __real_OQS_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state);
void __real_OQS_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen);
void __real_OQS_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state);
void __real_OQS_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state);
void __real_OQS_SHA3_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx *state);
void __real_OQS_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src);

void __real_OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen);
void __real_OQS_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state);
void __real_OQS_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen);
void __real_OQS_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state);
void __real_OQS_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state);
void __real_OQS_SHA3_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx *state);
void __real_OQS_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src);

void __real_OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
void __real_OQS_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state);
void __real_OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen);
void __real_OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state);
void __real_OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state);
void __real_OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state);
void __real_OQS_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src);
void __real_OQS_SHA3_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx *state);

void __real_OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen);
void __real_OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state);
void __real_OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen);
void __real_OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state);
void __real_OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state);
void __real_OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state);
void __real_OQS_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src);
void __real_OQS_SHA3_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx *state);

static void speed_profile_wrap_sha3_enter(void) {
        speed_profile_section_enter(SPEED_PROFILE_KIND_ALL, SPEED_PROFILE_SECTION_SHA3);
}

static void speed_profile_wrap_sha3_leave(void) {
        speed_profile_section_leave(SPEED_PROFILE_KIND_ALL, SPEED_PROFILE_SECTION_SHA3);
}

#define WRAP_SHA3_FUNCTION(name, ...)             \
        speed_profile_wrap_sha3_enter();          \
        __real_##name(__VA_ARGS__);               \
        speed_profile_wrap_sha3_leave();

void __wrap_OQS_SHA3_sha3_256(uint8_t *output, const uint8_t *input, size_t inplen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256, output, input, inplen);
}

void __wrap_OQS_SHA3_sha3_256_inc_init(OQS_SHA3_sha3_256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_init, state);
}

void __wrap_OQS_SHA3_sha3_256_inc_absorb(OQS_SHA3_sha3_256_inc_ctx *state, const uint8_t *input, size_t inlen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_absorb, state, input, inlen);
}

void __wrap_OQS_SHA3_sha3_256_inc_finalize(uint8_t *output, OQS_SHA3_sha3_256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_finalize, output, state);
}

void __wrap_OQS_SHA3_sha3_256_inc_ctx_release(OQS_SHA3_sha3_256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_ctx_release, state);
}

void __wrap_OQS_SHA3_sha3_256_inc_ctx_reset(OQS_SHA3_sha3_256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_ctx_reset, state);
}

void __wrap_OQS_SHA3_sha3_256_inc_ctx_clone(OQS_SHA3_sha3_256_inc_ctx *dest, const OQS_SHA3_sha3_256_inc_ctx *src) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_256_inc_ctx_clone, dest, src);
}

void __wrap_OQS_SHA3_sha3_384(uint8_t *output, const uint8_t *input, size_t inplen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384, output, input, inplen);
}

void __wrap_OQS_SHA3_sha3_384_inc_init(OQS_SHA3_sha3_384_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_init, state);
}

void __wrap_OQS_SHA3_sha3_384_inc_absorb(OQS_SHA3_sha3_384_inc_ctx *state, const uint8_t *input, size_t inlen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_absorb, state, input, inlen);
}

void __wrap_OQS_SHA3_sha3_384_inc_finalize(uint8_t *output, OQS_SHA3_sha3_384_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_finalize, output, state);
}

void __wrap_OQS_SHA3_sha3_384_inc_ctx_release(OQS_SHA3_sha3_384_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_ctx_release, state);
}

void __wrap_OQS_SHA3_sha3_384_inc_ctx_reset(OQS_SHA3_sha3_384_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_ctx_reset, state);
}

void __wrap_OQS_SHA3_sha3_384_inc_ctx_clone(OQS_SHA3_sha3_384_inc_ctx *dest, const OQS_SHA3_sha3_384_inc_ctx *src) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_384_inc_ctx_clone, dest, src);
}

void __wrap_OQS_SHA3_sha3_512(uint8_t *output, const uint8_t *input, size_t inplen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512, output, input, inplen);
}

void __wrap_OQS_SHA3_sha3_512_inc_init(OQS_SHA3_sha3_512_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_init, state);
}

void __wrap_OQS_SHA3_sha3_512_inc_absorb(OQS_SHA3_sha3_512_inc_ctx *state, const uint8_t *input, size_t inlen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_absorb, state, input, inlen);
}

void __wrap_OQS_SHA3_sha3_512_inc_finalize(uint8_t *output, OQS_SHA3_sha3_512_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_finalize, output, state);
}

void __wrap_OQS_SHA3_sha3_512_inc_ctx_release(OQS_SHA3_sha3_512_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_ctx_release, state);
}

void __wrap_OQS_SHA3_sha3_512_inc_ctx_reset(OQS_SHA3_sha3_512_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_ctx_reset, state);
}

void __wrap_OQS_SHA3_sha3_512_inc_ctx_clone(OQS_SHA3_sha3_512_inc_ctx *dest, const OQS_SHA3_sha3_512_inc_ctx *src) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_sha3_512_inc_ctx_clone, dest, src);
}

void __wrap_OQS_SHA3_shake128(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128, output, outlen, input, inplen);
}

void __wrap_OQS_SHA3_shake128_inc_init(OQS_SHA3_shake128_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_init, state);
}

void __wrap_OQS_SHA3_shake128_inc_absorb(OQS_SHA3_shake128_inc_ctx *state, const uint8_t *input, size_t inlen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_absorb, state, input, inlen);
}

void __wrap_OQS_SHA3_shake128_inc_finalize(OQS_SHA3_shake128_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_finalize, state);
}

void __wrap_OQS_SHA3_shake128_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake128_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_squeeze, output, outlen, state);
}

void __wrap_OQS_SHA3_shake128_inc_ctx_release(OQS_SHA3_shake128_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_ctx_release, state);
}

void __wrap_OQS_SHA3_shake128_inc_ctx_clone(OQS_SHA3_shake128_inc_ctx *dest, const OQS_SHA3_shake128_inc_ctx *src) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_ctx_clone, dest, src);
}

void __wrap_OQS_SHA3_shake128_inc_ctx_reset(OQS_SHA3_shake128_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake128_inc_ctx_reset, state);
}

void __wrap_OQS_SHA3_shake256(uint8_t *output, size_t outlen, const uint8_t *input, size_t inplen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256, output, outlen, input, inplen);
}

void __wrap_OQS_SHA3_shake256_inc_init(OQS_SHA3_shake256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_init, state);
}

void __wrap_OQS_SHA3_shake256_inc_absorb(OQS_SHA3_shake256_inc_ctx *state, const uint8_t *input, size_t inlen) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_absorb, state, input, inlen);
}

void __wrap_OQS_SHA3_shake256_inc_finalize(OQS_SHA3_shake256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_finalize, state);
}

void __wrap_OQS_SHA3_shake256_inc_squeeze(uint8_t *output, size_t outlen, OQS_SHA3_shake256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_squeeze, output, outlen, state);
}

void __wrap_OQS_SHA3_shake256_inc_ctx_release(OQS_SHA3_shake256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_ctx_release, state);
}

void __wrap_OQS_SHA3_shake256_inc_ctx_clone(OQS_SHA3_shake256_inc_ctx *dest, const OQS_SHA3_shake256_inc_ctx *src) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_ctx_clone, dest, src);
}

void __wrap_OQS_SHA3_shake256_inc_ctx_reset(OQS_SHA3_shake256_inc_ctx *state) {
        WRAP_SHA3_FUNCTION(OQS_SHA3_shake256_inc_ctx_reset, state);
}
