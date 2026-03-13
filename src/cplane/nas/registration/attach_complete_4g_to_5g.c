/**
 * @file registration/attach_complete_4g_to_5g.c
 * @brief 4G Attach Complete (0x43) → 5G Registration Complete (0x43)
 *
 * Phase 5 of NAS modularization.
 * Extracted from nas_4g_to_5g.c.
 *
 * Builds plain or integrity-protected 5G Registration Complete.
 * Sets PDU session establishment flag when pending.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "registration/registration.h"

int attach_complete_convert_4g_to_5g(uint8_t *nas_5g, size_t *nas_5g_len,
                                     ue_id_mapping_t *ue_map) {
	// 4G Attach Complete (0x43) -> 5G Registration Complete (0x43)
	// TS 24.301 (EPS) Attach Complete maps to TS 24.501 Registration complete
	// Build plain 5G NAS first
	size_t out = 0;
	if (*nas_5g_len < 4) {
		printf("[ERROR] Output buffer too small for Registration Complete\n");
		return -1;
	}
	nas_5g[out++] = 0x7E; // EPD 5GMM
	nas_5g[out++] = 0x00; // plain
	nas_5g[out++] = 0x43; // Registration complete
	nas_5g[out++] = 0x00; // no IEs

	// Integrity protect if 5G NAS keys available
	if (ue_map && ue_map->has_5g_nas_keys) {
		uint8_t mac[4];
		if (s1n2_compute_5g_uplink_mac(ue_map, nas_5g, out, mac) == 0) {
			uint8_t seq = (uint8_t)(ue_map->nas_ul_count_5g & 0xFF);
			size_t protected_len = 2 + 4 + 1 + out; // EPD+SecHdr + MAC + SEQ + inner
			if (*nas_5g_len < protected_len) {
				printf("[ERROR] Output buffer too small for protected Registration Complete\n");
				return -1;
			}
			uint8_t tmp[64];
			if (protected_len > sizeof(tmp)) {
				printf("[ERROR] Temporary buffer too small (%zu)\n", protected_len);
				return -1;
			}
			size_t off = 0;
			tmp[off++] = 0x7E; // EPD 5GMM
			tmp[off++] = 0x01; // Security header: integrity protected
			tmp[off++] = mac[0];
			tmp[off++] = mac[1];
			tmp[off++] = mac[2];
			tmp[off++] = mac[3];
			tmp[off++] = seq;
			memcpy(&tmp[off], nas_5g, out);
			off += out;
			memcpy(nas_5g, tmp, off);
			*nas_5g_len = off;
			printf("[INFO] Converted 4G Attach Complete -> 5G Registration Complete (integrity protected) [len=%zu]\n", off);
			printf("[DEBUG] RegComplete MAC=%02X %02X %02X %02X, SEQ=0x%02X\n", mac[0], mac[1], mac[2], mac[3], seq);
			ue_map->nas_ul_count_5g++;

			// Set flag to send PDU Session Establishment Request after this Registration Complete
			if (ue_map->has_pending_pdu_session) {
				ue_map->send_pdu_session_establishment = true;
				printf("[INFO] [RegComplete] Will send PDU Session Establishment Request after this message\n");
			}

			return 0;
		} else {
			printf("[WARN] Failed to compute MAC for Registration Complete, sending plain\n");
		}
	}
	*nas_5g_len = out;
	printf("[INFO] Converted 4G Attach Complete (0x43) -> 5G Registration Complete (plain) [len=%zu]\n", out);

	// Set flag to send PDU Session Establishment Request after this Registration Complete
	if (ue_map && ue_map->has_pending_pdu_session) {
		ue_map->send_pdu_session_establishment = true;
		printf("[INFO] [RegComplete] Will send PDU Session Establishment Request after this message\n");
	}

	return 0;
}
