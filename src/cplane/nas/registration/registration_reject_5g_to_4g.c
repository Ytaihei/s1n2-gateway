#include "s1n2_log.h"
/**
 * @file registration/registration_reject_5g_to_4g.c
 * @brief 5G Registration Reject (0x44) → 4G Attach Reject (0x44)
 *
 * Phase 5 of NAS modularization.
 * Extracted from nas_5g_to_4g.c (case 0x44).
 *
 * Simple cause code mapping — copies 5GMM cause to EMM cause.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "registration/registration.h"

int registration_reject_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                         uint8_t *nas_4g, size_t *nas_4g_len) {
	size_t offset = 3;
	if (offset >= msg_len) {
		LOG_WARN("5G NAS-PDU too short for 5GMM cause\n");
		return -1;
	}

	uint8_t fivegmm_cause = msg[offset++];

	if (*nas_4g_len < 3) {
		LOG_WARN("Output buffer too small for 4G Attach Reject\n");
		return -1;
	}

	size_t out_off = 0;
	nas_4g[out_off++] = 0x07;
	nas_4g[out_off++] = 0x44;
	nas_4g[out_off++] = fivegmm_cause;

	if (offset < msg_len) {
		LOG_INFO("5G Registration Reject contains %zu optional bytes (not converted)\n",
			   msg_len - offset);
	}

	*nas_4g_len = out_off;

	LOG_INFO("5G Registration Reject converted to 4G Attach Reject (cause=0x%02X)\n",
		   fivegmm_cause);
	return 0;
}
