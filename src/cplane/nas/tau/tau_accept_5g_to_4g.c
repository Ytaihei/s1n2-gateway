#include "s1n2_log.h"
/**
 * @file tau/tau_accept_5g_to_4g.c
 * @brief TAU Accept NAS message builder (4G EPS)
 *
 * Phase 6 of NAS modularization.
 * Moved from nas_builders.c.
 *
 * Builds a complete 4G Tracking Area Update Accept message including:
 *   - EPS Update Result derived from EPS Update Type
 *   - T3412 timer (default 9 minutes)
 *   - TAI list (from cached location or environment)
 *   - LAI (for combined TA/LA updates)
 *   - EPS bearer context status
 *   - NAS security wrapping (cipher + integrity or integrity-only)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "tau/tau.h"

/* ---- Static helpers (exclusive to TAU Accept builder) ---- */

static int s1n2_append_tai_list_lv(uint8_t *nas,
                                   size_t *offset,
                                   size_t capacity,
                                   const ue_id_mapping_t *ue_map) {
	if (!nas || !offset) {
		return -1;
	}
	uint8_t plmn[3] = {0};
	uint16_t tac16 = 0;
	bool have_cached = (ue_map && ue_map->has_location_info && ue_map->plmn_id_len >= 3);
	if (have_cached) {
		memcpy(plmn, ue_map->plmn_id, 3);
		tac16 = ue_map->tac;
	} else {
		char mcc[4] = {0};
		char mnc[4] = {0};
		int mnc_len = 3;
		s1n2_get_mcc_mnc_from_env(mcc, mnc, &mnc_len);
		s1n2_encode_plmn_tbcd(mcc, mnc, mnc_len, plmn);
		tac16 = s1n2_get_tac_from_env();
	}
	if ((*offset) + 8 > capacity) {
		LOG_ERROR("Not enough space to append TAI list IE (need 8, cap=%zu)\n",
		       capacity - *offset);
		return -1;
	}
	nas[(*offset)++] = 0x54; // IEI: Tracking Area Identity List
	nas[(*offset)++] = 0x06; // length of following value
	nas[(*offset)++] = 0x40; // type=2 (one PLMN with consecutive TACs), num=0
	memcpy(nas + *offset, plmn, 3);
	(*offset) += 3;
	nas[(*offset)++] = (uint8_t)((tac16 >> 8) & 0xFF);
	nas[(*offset)++] = (uint8_t)(tac16 & 0xFF);

	return 0;
}

static int s1n2_append_lai(uint8_t *nas,
                           size_t *offset,
                           size_t capacity,
                           const ue_id_mapping_t *ue_map) {
	if (!nas || !offset) {
		return -1;
	}
	if ((*offset) + 6 > capacity) {
		LOG_ERROR("Not enough space to append Location Area Identification IE\n");
		return -1;
	}
	uint8_t plmn[3] = {0};
	uint16_t lac16 = 0;
	bool have_cached = (ue_map && ue_map->has_location_info && ue_map->plmn_id_len >= 3);
	if (have_cached) {
		memcpy(plmn, ue_map->plmn_id, 3);
		lac16 = ue_map->tac;
	} else {
		char mcc[4] = {0};
		char mnc[4] = {0};
		int mnc_len = 3;
		s1n2_get_mcc_mnc_from_env(mcc, mnc, &mnc_len);
		s1n2_encode_plmn_tbcd(mcc, mnc, mnc_len, plmn);
		lac16 = s1n2_get_tac_from_env();
	}
	nas[(*offset)++] = 0x13; // IEI: Location Area Identification
	memcpy(nas + *offset, plmn, 3);
	*offset += 3;
	nas[(*offset)++] = (uint8_t)((lac16 >> 8) & 0xFF);
	nas[(*offset)++] = (uint8_t)(lac16 & 0xFF);

	return 0;
}

static uint16_t s1n2_build_eps_bearer_status_mask(const ue_id_mapping_t *map) {
	if (!map) {
		return 0;
	}
	uint8_t ebi = 5;
	if (map->ics_e_rab_id >= 1 && map->ics_e_rab_id <= 15) {
		ebi = (uint8_t)map->ics_e_rab_id;
	} else if (map->pdu_session_id >= 1 && map->pdu_session_id <= 15) {
		ebi = (uint8_t)map->pdu_session_id;
	}
	if (ebi > 15) {
		ebi = 5;
	}
	uint16_t mask = (uint16_t)(1u << ebi);
	LOG_TRACE("EPS bearer status mask built from EBI=%u (mask=0x%04X)\n", ebi, mask);

	return mask;
}

static int s1n2_finalize_downlink_plain_nas(ue_id_mapping_t *ue_map,
                                            const uint8_t *plain,
                                            size_t plain_len,
                                            uint8_t *out,
                                            size_t *out_len,
                                            const char *tag) {
	if (!plain || !out || !out_len) {
		return -1;
	}
	size_t cap = *out_len;
	if (plain_len > cap) {
		LOG_ERROR("[%s] Output buffer too small for NAS (len=%zu cap=%zu)\n",
		       tag ? tag : "DL", plain_len, cap);
		return -1;
	}
	if (!ue_map || !ue_map->has_nas_keys) {
		memcpy(out, plain, plain_len);
		*out_len = plain_len;
		LOG_INFO("[%s] Sending plain NAS (no security context)\n",
		       tag ? tag : "DL");

		return 0;
	}
	uint8_t eia_sel = ue_map->selected_nas_security_alg & 0x07;
	uint8_t eea_sel = (ue_map->selected_nas_security_alg >> 4) & 0x07;
	s1n2_nas_integrity_alg_t integ_alg = S1N2_NAS_EIA2;
	switch (eia_sel) {
	case 1: integ_alg = S1N2_NAS_EIA1; break;
	case 2: integ_alg = S1N2_NAS_EIA2; break;
	case 3: integ_alg = S1N2_NAS_EIA3; break;
	default:
		integ_alg = S1N2_NAS_EIA2;
		break;
	}
	uint32_t count_dl = ue_map->nas_dl_count;
	uint8_t seq = (uint8_t)(count_dl & 0xFF);
	uint8_t cipher_buf[512];
	const uint8_t *payload = plain;
	bool encrypted = false;
	if (eea_sel == 2) {
		if (plain_len <= sizeof(cipher_buf) &&
		    s1n2_nas_encrypt(S1N2_NAS_EEA2, ue_map->k_nas_enc,
		                     count_dl, 0, 1, plain, plain_len,
		                     cipher_buf) == 0) {
			payload = cipher_buf;
			encrypted = true;
			LOG_INFO("[%s] Applied NAS ciphering (EEA2, len=%zu)\n",
			       tag ? tag : "DL", plain_len);
		} else {
			LOG_WARN("[%s] Failed to cipher NAS (EEA=%u), falling back to integrity-only\n",
			       tag ? tag : "DL", eea_sel);
		}
	}
	uint8_t mac_input[1 + 512];
	if (plain_len > 512) {
		LOG_ERROR("[%s] NAS payload too large for MAC staging (%zu bytes)\n",
		       tag ? tag : "DL", plain_len);
		return -1;
	}
	mac_input[0] = seq;
	memcpy(mac_input + 1, payload, plain_len);
	uint8_t mac[4] = {0};
	if (s1n2_compute_smc_mac(integ_alg, ue_map->k_nas_int,
	                         count_dl, mac_input, 1 + plain_len,
	                         mac) != 0) {
		LOG_WARN("[%s] Failed to compute NAS MAC, sending plain message\n",
		       tag ? tag : "DL");
		memcpy(out, plain, plain_len);
		*out_len = plain_len;
		return 0;
	}
	size_t needed = 1 + 4 + 1 + plain_len;
	if (needed > cap) {
		LOG_ERROR("[%s] Output buffer too small after security wrapping (need %zu cap=%zu)\n",
		       tag ? tag : "DL", needed, cap);
		return -1;
	}
	uint8_t sec_header = encrypted ? 0x27 : 0x17;
	size_t out_off = 0;
	out[out_off++] = sec_header;
	memcpy(out + out_off, mac, 4);
	out_off += 4;
	out[out_off++] = seq;
	memcpy(out + out_off, payload, plain_len);
	out_off += plain_len;
	*out_len = out_off;
	uint32_t before = ue_map->nas_dl_count;
	ue_map->nas_dl_count = (ue_map->nas_dl_count + 1) & 0xFFFFFFFFu;
	LOG_INFO("[%s] Wrapped NAS with integrity%s (COUNT=0x%08X -> 0x%08X, seq=%u)\n",
	       tag ? tag : "DL",
	       encrypted ? "+cipher" : "",
	       before, ue_map->nas_dl_count, seq);

	return 0;
}

/* ================================================================
 * Public API: s1n2_build_tau_accept_nas
 * ================================================================ */

int s1n2_build_tau_accept_nas(s1n2_context_t *ctx,
                              ue_id_mapping_t *ue_map,
                              uint8_t eps_update_type_octet,
                              uint8_t *out,
                              size_t *out_len) {
	(void)ctx;
	if (!out || !out_len || *out_len == 0) {
		return -1;
	}
	uint8_t plain[256];
	size_t cap = sizeof(plain);
	size_t off = 0;
	plain[off++] = 0x07; // EPS MM PD + plain
	plain[off++] = 0x49; // TAU Accept (per detector)
	// EPS update result: Spare (bits 5-8) + EPS update result value (bits 1-4)
	// TS 24.301 Table 9.9.3.13.1: value in bits 1-4, spare in bits 5-8
	// BUG FIX: Lower 4 bits contain the EPS update type, not upper 4 bits
	// Old (wrong): eps_update_type_octet >> 4 - this extracted spare bits
	// New (correct): eps_update_type_octet & 0x07 - extracts actual update type from bits 1-3
	uint8_t eps_update_type = (uint8_t)(eps_update_type_octet & 0x07);
	LOG_INFO("[TAU-ACCEPT] EPS Update Type extraction: input_octet=0x%02X, extracted_type=%u\n",
	       eps_update_type_octet, eps_update_type);
	// TS 24.301 9.9.3.13: EPS update result values:
	//   0 = TA updating
	//   1 = Combined TA/LA updating (for eps_update_type 1 or 2)
	// Map eps_update_type to eps_update_result:
	//   type 0 (TA updating) -> result 0
	//   type 1 (Combined TA/LA) -> result 1
	//   type 2 (Combined TA/LA with IMSI attach) -> result 1
	//   type 3 (Periodic) -> result 0 (or 1 if combined attach was done)
	uint8_t eps_update_result;
	if (eps_update_type == 1 || eps_update_type == 2) {
		eps_update_result = 0x01;  // Combined TA/LA updating
		LOG_INFO("[TAU-ACCEPT] Combined TA/LA requested (type=%u) -> result=1\n", eps_update_type);
	} else {
		eps_update_result = 0x00;  // TA updating only
		LOG_INFO("[TAU-ACCEPT] TA updating only (type=%u) -> result=0\n", eps_update_type);
	}
	LOG_INFO("[TAU-ACCEPT] EPS Update Result: %u (%s)\n", eps_update_result,
	       eps_update_result == 1 ? "Combined TA/LA updating" : "TA updating");
	plain[off++] = (uint8_t)(eps_update_result & 0x07);  // Value in bits 1-4, spare 0 in bits 5-8
	plain[off++] = 0x29; // Default T3412 timer (9 minutes)
	if (s1n2_append_tai_list_lv(plain, &off, cap, ue_map) != 0) {
		LOG_WARN("[TAU-ACCEPT] Failed to append TAI list - continuing with defaults\n");
	}
	bool combined_la_required = (eps_update_type == 0x01 || eps_update_type == 0x02);
	if (combined_la_required) {
		if (s1n2_append_lai(plain, &off, cap, ue_map) != 0) {
			LOG_WARN("[TAU-ACCEPT] Failed to append LAI despite combined TA/LA request\n");
		}
	} else {
		LOG_TRACE("[TAU-ACCEPT] Skipping LAI (update type=%u)\n", eps_update_type);
	}
	uint16_t bearer_mask = s1n2_build_eps_bearer_status_mask(ue_map);
	if (bearer_mask) {
		if (off + 4 <= cap) {
			plain[off++] = 0x57;
			plain[off++] = 0x02;
			plain[off++] = (uint8_t)((bearer_mask >> 8) & 0xFF);
			plain[off++] = (uint8_t)(bearer_mask & 0xFF);
			LOG_TRACE("[TAU-ACCEPT] EPS bearer context status IE appended (mask=0x%04X)\n",
			       bearer_mask);
		} else {
			LOG_WARN("[TAU-ACCEPT] Not enough space for EPS bearer context status IE\n");
		}
	} else {
		LOG_TRACE("[TAU-ACCEPT] Skipped EPS bearer context status IE (no active bearer)\n");
	}
	size_t plain_len = off;
	LOG_TRACE("[TAU-ACCEPT] Plain NAS payload (len=%zu)\n", plain_len);
	s1n2_dump_hex("[TAU-ACCEPT-PLAIN]", plain, plain_len);
	size_t final_cap = *out_len;
	*out_len = final_cap;
	if (s1n2_finalize_downlink_plain_nas(ue_map, plain, plain_len,
	                                     out, out_len, "TAU-ACCEPT") != 0) {
		return -1;
	}
	return 0;
}
