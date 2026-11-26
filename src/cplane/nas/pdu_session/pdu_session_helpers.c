#include "s1n2_log.h"
/**
 * @file pdu_session/pdu_session_helpers.c
 * @brief PDU Session helper functions
 *
 * Extracted from nas_4g_to_5g_helpers.c during Phase 4 NAS modularization.
 *
 * Provides:
 *   - Active PDU context detection
 *   - PDU session ID inference
 *   - Cross-UE session mapping search (by IMSI/GUTI)
 *   - PDU session status mask encoding (IEI 0x50)
 *
 * @warning s1n2_find_session_mapping() searches all UE contexts.
 *          Assumes single-threaded access.
 *
 * @see 3GPP TS 24.501 § 9.11.3.44 (PDU session status)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_conversion_internal.h"
#include "pdu_session/pdu_session.h"

bool s1n2_has_active_pdu_context(const ue_id_mapping_t *map) {
	if (!map) {
		return false;
	}
	bool context_flags = map->ics_completed || map->has_upf_n3_info ||
		map->has_enb_s1u_info || map->has_s1n2_uplink_teid ||
		s1n2_context_should_preserve_teid(map);
	if (!context_flags) {
		return false;
	}
	return true;
}

uint8_t s1n2_infer_active_pdu_session_id(const ue_id_mapping_t *map) {
	if (!map) {
		return 0;
	}
	if (map->pdu_session_id >= 1 && map->pdu_session_id <= 16) {
		return map->pdu_session_id;
	}
	return 5; // default PSI for legacy single-session UEs
}

ue_id_mapping_t *s1n2_find_session_mapping(s1n2_context_t *ctx,
					   ue_id_mapping_t *current) {
	if (s1n2_has_active_pdu_context(current)) {
		return current;
	}
	if (!ctx) {
		return NULL;
	}
	const char *target_imsi = (current && current->imsi[0]) ? current->imsi : NULL;
	const uint8_t *target_guti = (current && current->has_last_5g_guti) ? current->last_5g_guti : NULL;
	uint8_t target_guti_len = (current && current->has_last_5g_guti) ? current->last_5g_guti_len : 0;
	ue_id_mapping_t *fallback = NULL;
	for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
		ue_id_mapping_t *entry = &ctx->ue_mappings[i];
		if (!entry->in_use || entry == current) {
			continue;
		}
		if (!s1n2_has_active_pdu_context(entry)) {
			continue;
		}
		if (target_imsi && entry->imsi[0] && strncmp(entry->imsi, target_imsi, sizeof(entry->imsi)) == 0) {
			return entry;
		}
		if (target_guti && entry->has_last_5g_guti &&
		    entry->last_5g_guti_len == target_guti_len &&
		    memcmp(entry->last_5g_guti, target_guti, target_guti_len) == 0) {
			return entry;
		}
		if (!fallback) {
			fallback = entry;
		}
	}
	return fallback;
}

uint16_t s1n2_build_pdu_session_status_mask(s1n2_context_t *ctx,
					    ue_id_mapping_t *ue_map) {
	ue_id_mapping_t *source = s1n2_find_session_mapping(ctx, ue_map);
	if (!s1n2_has_active_pdu_context(source)) {
		if (ue_map) {
			LOG_DEBUG("No active PDU context found for UE (ENB=%ld)\n", ue_map->enb_ue_s1ap_id);

		}
		return 0;
	}
	if (ue_map && source && source != ue_map) {
		if (ue_map->pdu_session_id < 1 && source->pdu_session_id >= 1) {
			ue_map->pdu_session_id = source->pdu_session_id;
		}
		if (!ue_map->has_last_5g_guti && source->has_last_5g_guti) {
			memcpy(ue_map->last_5g_guti, source->last_5g_guti, source->last_5g_guti_len);
			ue_map->last_5g_guti_len = source->last_5g_guti_len;
			ue_map->has_last_5g_guti = true;
		}
		if (!ue_map->has_last_access_type && source->has_last_access_type) {
			ue_map->has_last_access_type = true;
			ue_map->last_5gs_access_type = source->last_5gs_access_type;
		}
		LOG_DEBUG("Using cached UE mapping (ENB=%ld) for PDU Session Status (PSI=%u)\n",
		       source->enb_ue_s1ap_id, source->pdu_session_id);

	}
	uint8_t psi = s1n2_infer_active_pdu_session_id(source);
	if (psi < 1 || psi > 15) {
		LOG_WARN("Unable to encode PDU Session Status (psi=%u out of range)\n", psi);

		return 0;
	}
	uint16_t mask = (uint16_t)(1u << psi);
	LOG_DEBUG("Built PDU Session Status mask from psi=%u (mask=0x%04X)\n",
		psi, mask);

	return mask;
}

int s1n2_append_pdu_session_status(uint8_t *nas,
				   size_t *offset,
				   size_t capacity,
				   uint16_t status_mask) {
	if (!nas || !offset) {
		return -1;
	}
	if ((*offset) + 4 > capacity) {
		LOG_ERROR("Not enough space to append PDU Session Status IE\n");
		return -1;
	}
	nas[(*offset)++] = S1N2_5GS_IEI_PDU_SESSION_STATUS;
	nas[(*offset)++] = 0x02;
	uint8_t lsb = (uint8_t)(status_mask & 0xFF);
	uint8_t msb = (uint8_t)((status_mask >> 8) & 0xFF);
	/*
	 * NOTE: write LSB first so that Open5GS's internal byte swap recreates the
	 * intended PSI bitmask (legacy quirk confirmed via AMF logs).
	 */
	nas[(*offset)++] = lsb;
	nas[(*offset)++] = msb;
	LOG_TRACE("Encoded PDU Session Status IE (mask=0x%04X, bytes=%02X %02X)\n",
	       status_mask, lsb, msb);

	return 0;
}
