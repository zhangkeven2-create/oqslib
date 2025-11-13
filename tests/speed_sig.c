// SPDX-License-Identifier: MIT

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#if defined(OQS_USE_RASPBERRY_PI)
#define _OQS_RASPBERRY_PI
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
#define SPEED_USE_ARM_PMU
#endif
#include "ds_benchmark.h"
#include "system_info.c"
#include "speed_profile_bench.h"

typedef struct {
        OQS_SIG *sig;
        uint8_t *public_key;
        uint8_t *secret_key;
        uint8_t *message;
        size_t message_len;
        uint8_t *signature;
        size_t *signature_len;
} speed_sig_context;

static OQS_STATUS sig_keypair_op(void *ctx_) {
        speed_sig_context *ctx = (speed_sig_context *) ctx_;
        return OQS_SIG_keypair(ctx->sig, ctx->public_key, ctx->secret_key);
}

static OQS_STATUS sig_sign_op(void *ctx_) {
        speed_sig_context *ctx = (speed_sig_context *) ctx_;
        return OQS_SIG_sign(ctx->sig, ctx->signature, ctx->signature_len, ctx->message, ctx->message_len, ctx->secret_key);
}

static OQS_STATUS sig_verify_op(void *ctx_) {
        speed_sig_context *ctx = (speed_sig_context *) ctx_;
        return OQS_SIG_verify(ctx->sig, ctx->message, ctx->message_len, ctx->signature, *(ctx->signature_len), ctx->public_key);
}

static OQS_STATUS sig_fullcycle_op(void *ctx_);

static void fullcycle(OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key, uint8_t *signature, size_t *signature_len, uint8_t *message, size_t message_len) {
        if (OQS_SIG_keypair(sig, public_key, secret_key) != OQS_SUCCESS) {
                printf("keygen error. Exiting.\n");
                exit(-1);
	}
	if (OQS_SIG_sign(sig, signature, signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
		printf("sign error. Exiting.\n");
		exit(-1);
	}
	if (OQS_SIG_verify(sig, message, message_len, signature, *signature_len, public_key) != OQS_SUCCESS) {
		printf("verify error. Exiting.\n");
		exit(-1);
	}
}

static OQS_STATUS sig_fullcycle_op(void *ctx_) {
        speed_sig_context *ctx = (speed_sig_context *) ctx_;
        fullcycle(ctx->sig, ctx->public_key, ctx->secret_key, ctx->signature, ctx->signature_len, ctx->message, ctx->message_len);
        return OQS_SUCCESS;
}

static bool has_prefix(const char *name, const char *prefix) {
        if (name == NULL || prefix == NULL) {
                return false;
        }
        size_t prefix_len = strlen(prefix);
        return strncmp(name, prefix, prefix_len) == 0;
}

static bool is_ml_dsa_alg(const char *name) {
        return has_prefix(name, "ML-DSA-") || has_prefix(name, "ml_dsa_");
}

static bool is_slh_dsa_alg(const char *name) {
        return has_prefix(name, "SLH-DSA") || has_prefix(name, "SLH_DSA") || has_prefix(name, "slh_dsa");
}

static bool is_allowed_sig_alg(const char *name) {
        return is_ml_dsa_alg(name) || is_slh_dsa_alg(name);
}

static OQS_STATUS sig_speed_wrapper(const char *method_name, uint64_t duration, bool printInfo, bool doFullCycle) {

        OQS_SIG *sig = NULL;
	uint8_t *public_key = NULL;
	uint8_t *secret_key = NULL;
	uint8_t *message = NULL;
	uint8_t *signature = NULL;
	size_t message_len = 50;
	size_t signature_len = 0;
	OQS_STATUS ret = OQS_ERROR;

	sig = OQS_SIG_new(method_name);
	if (sig == NULL) {
		return OQS_SUCCESS;
	}

	public_key = OQS_MEM_malloc(sig->length_public_key);
	secret_key = OQS_MEM_malloc(sig->length_secret_key);
	message = OQS_MEM_malloc(message_len);
	signature = OQS_MEM_malloc(sig->length_signature);

	if ((public_key == NULL) || (secret_key == NULL) || (message == NULL) || (signature == NULL)) {
		fprintf(stderr, "ERROR: OQS_MEM_malloc failed\n");
		goto err;
	}

	OQS_randombytes(message, message_len);

        printf("%-36s | %10s | %14s | %15s | %10s | %25s | %10s\n", sig->method_name, "", "", "", "", "", "");
        speed_sig_context ctx = {
                .sig = sig,
                .public_key = public_key,
                .secret_key = secret_key,
                .message = message,
                .message_len = message_len,
                .signature = signature,
                .signature_len = &signature_len,
        };
        speed_profile_mask_t profile_mask = is_ml_dsa_alg(sig->method_name) ? SPEED_PROFILE_KIND_MLDSA : SPEED_PROFILE_KIND_NONE;

        if (!doFullCycle) {
                if (speed_profile_run_benchmark("keypair", duration, profile_mask, sig_keypair_op, &ctx) != OQS_SUCCESS) {
                        goto err;
                }
                if (speed_profile_run_benchmark("sign", duration, profile_mask, sig_sign_op, &ctx) != OQS_SUCCESS) {
                        goto err;
                }
                if (speed_profile_run_benchmark("verify", duration, profile_mask, sig_verify_op, &ctx) != OQS_SUCCESS) {
                        goto err;
                }
        } else {
                if (speed_profile_run_benchmark("fullcycle", duration, profile_mask, sig_fullcycle_op, &ctx) != OQS_SUCCESS) {
                        goto err;
                }
        }


	if (printInfo) {
		printf("public key bytes: %zu, secret key bytes: %zu, signature bytes: %zu\n", sig->length_public_key, sig->length_secret_key, sig->length_signature);
		if (signature_len != sig->length_signature) {
			printf("   Actual signature length returned (%zu) less than declared maximum signature length (%zu)\n", signature_len, sig->length_signature);
		}
	}

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;

cleanup:
	if (sig != NULL) {
		OQS_MEM_secure_free(secret_key, sig->length_secret_key);
	}
	OQS_MEM_insecure_free(public_key);
	OQS_MEM_insecure_free(signature);
	OQS_MEM_insecure_free(message);
	OQS_SIG_free(sig);

	return ret;
}

static OQS_STATUS printAlgs(void) {
        for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
                const char *name = OQS_SIG_alg_identifier(i);
                if (!is_allowed_sig_alg(name)) {
                        continue;
                }
                OQS_SIG *sig = OQS_SIG_new(name);
                if (sig == NULL) {
                        printf("%s (disabled)\n", name);
                } else {
                        printf("%s\n", name);
                }
                OQS_SIG_free(sig);
        }
        return OQS_SUCCESS;
}

int main(int argc, char **argv) {

	int ret = EXIT_SUCCESS;
	OQS_STATUS rc;

	bool printUsage = false;
	uint64_t duration = 3;
	bool printSigInfo = false;
	bool doFullCycle = false;

	OQS_SIG *single_sig = NULL;

	OQS_init();
#ifdef OQS_USE_OPENSSL
	rc = OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl);
	if (rc != OQS_SUCCESS) {
		printf("Could not generate random data with OpenSSL RNG\n");
		OQS_destroy();
		return EXIT_FAILURE;
	}
#endif

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--algs") == 0) {
			rc = printAlgs();
			if (rc == OQS_SUCCESS) {
				OQS_destroy();
				return EXIT_SUCCESS;
			} else {
				OQS_destroy();
				return EXIT_FAILURE;
			}
		} else if ((strcmp(argv[i], "--duration") == 0) || (strcmp(argv[i], "-d") == 0)) {
			if (i < argc - 1) {
				duration = (uint64_t)strtol(argv[i + 1], NULL, 10);
				if (duration > 0) {
					i += 1;
					continue;
				}
			}
		} else if ((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0)) {
			printUsage = true;
			break;
		} else if ((strcmp(argv[i], "--info") == 0) || (strcmp(argv[i], "-i") == 0)) {
			printSigInfo = true;
			continue;
		} else if ((strcmp(argv[i], "--fullcycle") == 0) || (strcmp(argv[i], "-f") == 0)) {
			doFullCycle = true;
			continue;
                } else {
                        single_sig = OQS_SIG_new(argv[i]);
                        if (single_sig == NULL || !is_allowed_sig_alg(argv[i])) {
                                if (single_sig != NULL) {
                                        OQS_SIG_free(single_sig);
                                }
                                single_sig = NULL;
                                printUsage = true;
                                break;
                        }
                }
        }

	if (printUsage) {
		fprintf(stderr, "Usage: speed_sig <options> <alg>\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "<options>\n");
		fprintf(stderr, "--algs             Print supported algorithms and terminate\n");
		fprintf(stderr, "--duration n\n");
		fprintf(stderr, " -d n              Run each speed test for approximately n seconds, default n=3\n");
		fprintf(stderr, "--help\n");
		fprintf(stderr, " -h                Print usage\n");
		fprintf(stderr, "--info\n");
		fprintf(stderr, " -i                Print info (sizes, security level) about each SIG\n");
		fprintf(stderr, "--fullcycle\n");
		fprintf(stderr, " -f                Test full keygen-sign-verify cycle of each SIG\n");
		fprintf(stderr, "\n");
                fprintf(stderr, "<alg>              Only run the specified SIG method; must be one of the algorithms output by --algs\n");
                fprintf(stderr, "Note: Only ML-DSA and SLH-DSA algorithms are benchmarked by default.\n");
                OQS_destroy();
                return EXIT_FAILURE;
        }

	print_system_info();

	printf("Speed test\n");
	printf("==========\n");

	PRINT_TIMER_HEADER
        if (single_sig != NULL) {
                rc = sig_speed_wrapper(single_sig->method_name, duration, printSigInfo, doFullCycle);
                if (rc != OQS_SUCCESS) {
                        ret = EXIT_FAILURE;
                }
                OQS_SIG_free(single_sig);

        } else {
                for (size_t i = 0; i < OQS_SIG_algs_length; i++) {
                        const char *name = OQS_SIG_alg_identifier(i);
                        if (!is_allowed_sig_alg(name)) {
                                continue;
                        }
                        rc = sig_speed_wrapper(name, duration, printSigInfo, doFullCycle);
                        if (rc != OQS_SUCCESS) {
                                ret = EXIT_FAILURE;
                        }
		}
	}
	PRINT_TIMER_FOOTER
	OQS_destroy();

	return ret;
}
