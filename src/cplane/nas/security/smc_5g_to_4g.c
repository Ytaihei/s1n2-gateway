/**
 * @file security/smc_5g_to_4g.c
 * @brief 5G Security Mode Command → 4G Security Mode Command conversion
 *
 * Extracted from nas_5g_to_4g_helpers.c during Phase 3 NAS modularization.
 *
 * Converts 5G Security Mode Command (MT=0x5D) to 4G Security Mode Command:
 *   - Maps NAS security algorithms: NEA→EEA, NIA→EIA
 *   - Replays UE security capability
 *   - Computes 4G NAS integrity MAC (if keys available)
 *   - Initializes DL COUNT to 0
 *
 * @warning DL COUNT is reset to 0 when sending SMC. This matches Open5GS
 *          behavior (new_security_context resets dl_count).
 *
 * @see 3GPP TS 24.301 § 8.2.20 (Security mode command)
 * @see 3GPP TS 24.501 § 8.2.25 (Security mode command)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "security/security.h"

int smc_convert_5g_to_4g(const uint8_t *payload,
                         size_t payload_len,
                         uint8_t *nas_4g,
                         size_t *nas_4g_len,
                         s1n2_security_mode_info_t *info,
                         const uint8_t *mac,
                         bool mac_present,
                         uint8_t seq_no,
                         const ue_id_mapping_t *security_cache) {
	if (!payload || payload_len < 5 || !nas_4g || !nas_4g_len) {
		return -1;
	}

	size_t pos = 0;
	uint8_t plain_pd = payload[pos++];
	uint8_t plain_sec_hdr = payload[pos++];
	(void)plain_sec_hdr;
	uint8_t msg_type = payload[pos++];

	if (msg_type != 0x5D) {
		return -1;
	}

	if (payload_len < pos + 2) {
		s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
							"payload too short for mandatory fields");
		return -1;
	}

	uint8_t selected_alg_5g = payload[pos++];
	uint8_t ngksi_octet = payload[pos++];

	if (payload_len <= pos) {
		s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
							"missing UE security capability");
		return -1;
	}

	uint8_t ue_sec_cap_len = payload[pos++];
	if (pos + ue_sec_cap_len > payload_len) {
		s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
							"UE security capability truncated");
		return -1;
	}

	uint8_t ue_sec_cap_buf[S1N2_MAX_UE_SECURITY_CAP_LEN] = {0};
	uint8_t copy_len = (ue_sec_cap_len > sizeof(ue_sec_cap_buf))
					 ? sizeof(ue_sec_cap_buf)
					 : ue_sec_cap_len;
	memcpy(ue_sec_cap_buf, payload + pos, copy_len);
	pos += ue_sec_cap_len;

	bool imeisv_requested = false;
	bool additional_present = false;
	uint8_t additional_value = 0;

	while (pos < payload_len) {
		uint8_t iei = payload[pos++];

		if ((iei & 0xF0) == 0xE0) {
			imeisv_requested = (iei & 0x01) != 0;
			continue;
		}

		if (pos >= payload_len) {
			s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
									"unexpected end of NAS while parsing IE");
			return -1;
		}

		uint8_t len = payload[pos++];
		if (pos + len > payload_len) {
			s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
									"IE length exceeds remaining NAS payload");
			return -1;
		}

		if (iei == 0x36) {
			if (len > 0) {
				additional_value = payload[pos];
			}
			additional_present = (len > 0);
		}

		pos += len;
	}

	uint8_t nea = (selected_alg_5g >> 4) & 0x0F;
	uint8_t nia = selected_alg_5g & 0x0F;
	uint8_t eea = (nea < 8) ? s1n2_nea_to_eea_map[nea] : 0;
	uint8_t eia = (nia < 8) ? s1n2_nia_to_eia_map[nia] : 0;

	// TS 24.301 9.9.3.23: NAS security algorithms
	// |7|6|5|4|3|2|1|0|
	//  0  EEA    0  EIA
	// Bits 7,3: Spare (0), Bits 6-4: EEA, Bits 2-0: EIA
	uint8_t selected_alg_4g = (uint8_t)(((eea & 0x07) << 4) | (eia & 0x07));
	printf("[DEBUG] Selected NAS alg mapping: 5G (nea=%u, nia=%u) -> 4G (eea=%u, eia=%u, octet=0x%02X)\n",
	    nea, nia, eea, eia, selected_alg_4g);
	uint8_t eea_byte = (ue_sec_cap_len >= 3) ? ue_sec_cap_buf[2] : 0x00;
	uint8_t eia_byte = (ue_sec_cap_len >= 4) ? ue_sec_cap_buf[3] : 0x00;
	uint8_t eea_eps = eea_byte;
	uint8_t eia_eps = eia_byte;
	printf("[DEBUG] EPS capability fallback: using 5G EEA byte=0x%02X, EIA byte=0x%02X\n",
	       eea_eps, eia_eps);

	uint8_t replay_cap[S1N2_MAX_UE_SECURITY_CAP_LEN] = {0};
	size_t replay_len = 0;

	// Use original 4G UE network capability from Attach Request (if cached)
	if (security_cache && security_cache->has_ue_network_cap_4g &&
		security_cache->ue_network_cap_4g_len > 0) {
		replay_len = security_cache->ue_network_cap_4g_len;
		if (replay_len > S1N2_MAX_UE_SECURITY_CAP_LEN) {
			replay_len = S1N2_MAX_UE_SECURITY_CAP_LEN;
		}
		memcpy(replay_cap, security_cache->ue_network_cap_4g, replay_len);
		printf("[INFO] Using cached 4G UE network capability from Attach Request (len=%zu): ", replay_len);
		for (size_t i = 0; i < replay_len; i++) {
			printf("%02X ", replay_cap[i]);
		}
		printf("\n");
	} else if (security_cache && security_cache->has_cached_ue_security_cap &&
		security_cache->cached_ue_security_cap_len > 0) {
		// Fallback to 5G-derived capability if 4G original not available
		replay_len = security_cache->cached_ue_security_cap_len;
		if (replay_len > S1N2_MAX_UE_SECURITY_CAP_LEN) {
			replay_len = S1N2_MAX_UE_SECURITY_CAP_LEN;
		}
		memcpy(replay_cap, security_cache->cached_ue_security_cap, replay_len);
		printf("[DEBUG] Using cached 5G-derived UE security capability (4G not available, len=%zu)\n", replay_len);
	} else {
		replay_len = 2;
		replay_cap[0] = eea_eps;
		replay_cap[1] = eia_eps;
		printf("[WARN] No cached UE security capability available; falling back to EPS-only (%02X %02X)\n",
		   replay_cap[0], replay_cap[1]);
	}

	// Step 1: Build plain NAS message (security header type 0)
	uint8_t plain_nas[512];
	size_t plain_len = 0;

	plain_nas[plain_len++] = 0x07; // Security header type 0 + EPS MM PD
	plain_nas[plain_len++] = 0x5D; // Security Mode Command
	plain_nas[plain_len++] = selected_alg_4g;
	plain_nas[plain_len++] = (uint8_t)(ngksi_octet & 0x0F);

	plain_nas[plain_len++] = (uint8_t)replay_len;
	if (replay_len > 0) {
		memcpy(plain_nas + plain_len, replay_cap, replay_len);
		plain_len += replay_len;
	}

	if (imeisv_requested) {
		plain_nas[plain_len++] = (uint8_t)(0xC0 | 0x01);
		printf("[DEBUG] Added IMEISV request IE for 4G (IEI=0xC1)\n");
	}

	if (additional_present) {
		printf("[DEBUG] Skipping Additional 5G security info IE (value=0x%02X) for 4G SMC\n",
			additional_value);
	}

	// Step 2: Compute MAC if keys are available
	bool use_integrity = false;
	uint8_t computed_mac[4] = {0};
	uint32_t count_value = 0;

	if (security_cache && security_cache->has_nas_keys) {
		// Determine integrity algorithm from selected_alg_4g
		uint8_t eia_alg = selected_alg_4g & 0x07;
		s1n2_nas_integrity_alg_t alg = S1N2_NAS_EIA0;

		switch (eia_alg) {
			case 0: alg = S1N2_NAS_EIA0; break;
			case 1: alg = S1N2_NAS_EIA1; break;
			case 2: alg = S1N2_NAS_EIA2; break;
			case 3: alg = S1N2_NAS_EIA3; break;
			default:
				printf("[WARN] Unknown EIA algorithm %u, defaulting to EIA0\n", eia_alg);
				alg = S1N2_NAS_EIA0;
				break;
		}

		count_value = security_cache->nas_dl_count;

		printf("[DEBUG] Using K_NASint for MAC: ");
		for (int i = 0; i < 16; i++) {
			printf("%02X", security_cache->k_nas_int[i]);
		}
		printf("\n");

		// Build MAC input: sequence number (COUNT LSB) + plain NAS message
		// This matches srsRAN UE behavior (&pdu->msg[seq_offset] where seq_offset=5)
		uint8_t mac_input[513];  // 1 byte seq + 512 max plain_nas
		mac_input[0] = (uint8_t)(count_value & 0xFF);  // Sequence number
		memcpy(mac_input + 1, plain_nas, plain_len);
		size_t mac_input_len = 1 + plain_len;

		printf("[DEBUG] MAC input for SMC (%zu bytes): ", mac_input_len);
		for (size_t i = 0; i < mac_input_len; i++) {
			printf("%02X ", mac_input[i]);
		}
		printf("\n");

		if (s1n2_compute_smc_mac(alg, security_cache->k_nas_int, count_value,
		                         mac_input, mac_input_len, computed_mac) == 0) {
			use_integrity = true;
			printf("[INFO] Computed 4G NAS MAC for SMC: %02X %02X %02X %02X (COUNT=0x%08X, EIA=%u)\n",
			       computed_mac[0], computed_mac[1], computed_mac[2], computed_mac[3],
			       count_value, eia_alg);
		} else {
			printf("[WARN] Failed to compute NAS MAC, sending plain SMC\n");
		}
	} else {
		printf("[WARN] No NAS keys available in security_cache, sending plain SMC\n");
	}

	// Step 3: Build final message with or without integrity protection
	size_t mac_overhead = use_integrity ? 5 : 0; /* 4-byte MAC + sequence */
	size_t required_len = 1 /* security header+PD */
				   + mac_overhead
				   + plain_len; /* plain NAS message content */

	if (*nas_4g_len < required_len) {
		s1n2_log_security_mode_result("downlink", false, plain_pd, msg_type,
							"output buffer too small");
		return -1;
	}

	size_t out = 0;

	if (use_integrity) {
		// Integrity-protected message (security header type 3)
		nas_4g[out++] = 0x37; // Security header type 3 + EPS MM PD
		memcpy(nas_4g + out, computed_mac, 4);
		out += 4;
		nas_4g[out++] = (uint8_t)(count_value & 0xFF); // Sequence number (LSB of COUNT)
	}

	// Copy plain NAS message
	memcpy(nas_4g + out, plain_nas, plain_len);
	out += plain_len;

	*nas_4g_len = out;

	if (info) {
		info->has_security_mode = true;
		info->has_selected_alg_5g = true;
		info->selected_alg_5g = selected_alg_5g;
		info->selected_alg_4g = selected_alg_4g;
		info->ngksi = ngksi_octet & 0x07;
		info->ngksi_octet = ngksi_octet;
		info->imeisv_requested = imeisv_requested;
		info->additional_security_info_present = additional_present;
		info->additional_security_info = additional_value;
		info->has_ue_security_cap = (replay_len > 0);
		size_t store_len = (replay_len > S1N2_MAX_UE_SECURITY_CAP_LEN)
					 ? S1N2_MAX_UE_SECURITY_CAP_LEN
					 : replay_len;
		info->ue_security_cap_len = (uint8_t)store_len;
		if (store_len > 0) {
			memcpy(info->ue_security_cap, replay_cap, store_len);
		}
		info->has_ue_security_cap_5g = (copy_len > 0);
		size_t store_len_5g = (copy_len > S1N2_MAX_UE_SECURITY_CAP_LEN)
				 ? S1N2_MAX_UE_SECURITY_CAP_LEN
				 : copy_len;
		info->ue_security_cap_5g_len = (uint8_t)store_len_5g;
		if (store_len_5g > 0) {
			memcpy(info->ue_security_cap_5g, ue_sec_cap_buf, store_len_5g);
		}
	}

	char detail_buf[128];
	if (use_integrity) {
		snprintf(detail_buf, sizeof(detail_buf),
			 "alg=0x%02X, ngKSI=%u, INTEGRITY-PROTECTED (MAC computed), len=%zu",
			 selected_alg_4g, ngksi_octet & 0x07, *nas_4g_len);
	} else {
		snprintf(detail_buf, sizeof(detail_buf),
			 "alg=0x%02X, ngKSI=%u, PLAIN (no MAC), len=%zu",
			 selected_alg_4g, ngksi_octet & 0x07, *nas_4g_len);
	}
	s1n2_log_security_mode_result("downlink", true, plain_pd, msg_type, detail_buf);

	printf("[DEBUG] 4G Security Mode Command bytes: ");
	for (size_t i = 0; i < *nas_4g_len && i < 32; i++) {
		printf("%02X ", nas_4g[i]);
	}
	if (*nas_4g_len > 32) printf("...");
	printf("\n");
	fflush(stdout);

	// Initialize DL COUNT to 0 when sending Security Mode Command
	// This matches Open5GS behavior (new_security_context resets dl_count)
	if (security_cache && security_cache->has_nas_keys) {
		ue_id_mapping_t *mutable_cache = (ue_id_mapping_t *)security_cache;
		mutable_cache->nas_dl_count = 0;
		printf("[DEBUG] [SMC] Initialized 4G DL COUNT to 0 (new security context)\n");
		fflush(stdout);
	}

	return 0;
}

/* Backward-compatible wrapper: old API name delegates to new function */
int s1n2_convert_smc_5g_to_4g(const uint8_t *payload,
                               size_t payload_len,
                               uint8_t *nas_4g,
                               size_t *nas_4g_len,
                               s1n2_security_mode_info_t *info,
                               const uint8_t *mac,
                               bool mac_present,
                               uint8_t seq_no,
                               const ue_id_mapping_t *security_cache) {
	return smc_convert_5g_to_4g(payload, payload_len, nas_4g, nas_4g_len,
	                            info, mac, mac_present, seq_no, security_cache);
}
