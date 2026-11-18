#include "s1n2_log.h"
/**
 * @file nas_5g_to_4g.c
 * @brief Downlink NAS dispatcher: 5G (5GS) → 4G (EPS) message routing
 *
 * Dispatcher that delegates security header processing to
 * security/nas_5g_security_unwrap.c and routes the plain NAS message
 * to per-module converters (auth, security, registration).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "auth/auth.h"
#include "registration/registration.h"
#include "registration/registration_bridge.h"
#include "security/security.h"

int convert_5g_nas_to_4g(const uint8_t *nas_5g, size_t nas_5g_len,
					 uint8_t *nas_4g, size_t *nas_4g_len,
					 s1n2_security_mode_info_t *info,
					 ue_id_mapping_t *security_cache) {
	if (info) {
		memset(info, 0, sizeof(*info));
	}

	if (!nas_5g || !nas_4g || !nas_4g_len || nas_5g_len < 3) {
		return -1;
	}

	LOG_DEBUG("Converting 5G NAS-PDU to 4G (input len=%zu)\n", nas_5g_len);

	/* ---- Security header processing (delegated) ---- */
	uint8_t decrypted_nas_buf[512];
	const uint8_t *msg = NULL;
	size_t msg_len = 0;
	uint8_t mac_buf[4] = {0};
	bool mac_present = false;
	uint8_t sequence_number = 0;

	int unwrap_rc = nas_5g_security_unwrap(
		nas_5g, nas_5g_len, security_cache,
		&msg, &msg_len,
		decrypted_nas_buf, sizeof(decrypted_nas_buf),
		mac_buf, &mac_present, &sequence_number);

	if (unwrap_rc != 0) {
		return -1;
	}
	if (msg_len < 3) {
		s1n2_log_security_mode_result("downlink", false, nas_5g[0], 0,
									  "short payload after security header");
		return -1;
	}

	uint8_t msg_type = msg[2];

	if (msg_type == 0x5D) {
		size_t original_cap = *nas_4g_len;
		const uint8_t *mac_ptr = mac_present ? mac_buf : NULL;
		int rc = s1n2_convert_smc_5g_to_4g(msg, msg_len, nas_4g, nas_4g_len,
					   info, mac_ptr, mac_present, sequence_number,
							   security_cache);
		if (rc != 0) {
			*nas_4g_len = original_cap;
		}
		// For downlink SMC we didn't wrap with integrity here (s1n2_convert_smc_5g_to_4g may do). Ensure COUNT-DL increment for subsequent DL NAS.
		if (security_cache && security_cache->has_nas_keys) {
			uint32_t before = security_cache->nas_dl_count;
			security_cache->nas_dl_count = (security_cache->nas_dl_count + 1) & 0xFFFFFFFFu;
			LOG_DEBUG("[COUNT] DL NAS COUNT++ after SMC conversion: 0x%08X -> 0x%08X\n", before, security_cache->nas_dl_count);
		}
		return rc;
	}

	if (msg[0] != 0x7E) {
		LOG_WARN("5G NAS-PDU does not start with 0x7E, skipping conversion\n");
		return -1;
	}

	uint8_t security_header = msg[1];
	LOG_DEBUG("5G NAS header: security=0x%02X, msg_type=0x%02X\n", security_header, msg_type);

	switch (msg_type) {
	case 0x42: { // 5G Registration Accept -> 4G Attach Accept
			/* EXTRACTED to registration/registration_accept_5g_to_4g.c (Phase 5) */
			if (!security_cache) return -1;
            if (!security_cache->has_pdu_ipv4) {
                if (msg_len > sizeof(security_cache->pending_registration_accept)) return -1;
                memcpy(security_cache->pending_registration_accept, msg, msg_len);
                security_cache->pending_registration_accept_len = msg_len;
                *nas_4g_len = 0;
                return 1; /* Consumed: defer EPS attach until SMF provides an address. */
            }
            return registration_accept_convert_5g_to_4g(msg, msg_len, nas_4g, nas_4g_len, security_cache);
		}
        case 0x68:
            if (s1n2_cache_pdu_address(security_cache, msg, msg_len) != 0) return -1;
            *nas_4g_len = 0;
            return 1;
		case 0x56: {
			/* Delegated to auth module (Phase 2 extraction) */
			return auth_request_convert_5g_to_4g(msg, msg_len, nas_4g, nas_4g_len);
		}
		case 0x44: {
			/* EXTRACTED to registration/registration_reject_5g_to_4g.c (Phase 5) */
			return registration_reject_convert_5g_to_4g(msg, msg_len, nas_4g, nas_4g_len);
		}
		default:
			LOG_WARN("5G NAS message type 0x%02X not supported for conversion\n", msg_type);
			return -1;
	}

	return -1;
}
