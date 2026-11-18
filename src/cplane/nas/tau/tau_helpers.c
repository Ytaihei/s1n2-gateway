#include "s1n2_log.h"
/**
 * @file tau/tau_helpers.c
 * @brief Helper functions for TAU (Tracking Area Update) conversion
 *
 * Contains functions for TAU message mapping, registration type encoding,
 * and TAU-specific IE appending.
 *
 * Extracted from nas_4g_to_5g_helpers.c during Phase 1 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_conversion_internal.h"

/* ================================================================
 * TAU / Mobility type mapping helpers
 * ================================================================ */

/**
 * @brief Map EPS Update Type to 5GS Registration Type
 *
 * Converts 4G EPS mobility update type to corresponding 5G registration type.
 * Handles initial attach, TAU, and periodic registration scenarios.
 *
 * @param eps_update_type 3-bit EPS Update Type value
 * @return 5GS Registration Type (0x01=Initial, 0x02=Mobility, 0x03=Periodic)
 */
uint8_t s1n2_map_eps_update_type(uint8_t eps_update_type) {
	uint8_t value = eps_update_type & 0x07;
	switch (value) {
	case 0:
	case 1:
	case 2:
		return S1N2_5GS_REG_TYPE_MOBILITY;
	case 3:
		return S1N2_5GS_REG_TYPE_PERIODIC;
	default:
		return S1N2_5GS_REG_TYPE_INITIAL;
	}
}

/**
 * @brief Map EPS Update Type to 5GS Update Type IE
 *
 * Converts 4G EPS update type to 5G Update Type IE for Registration/TAU Request.
 *
 * @param eps_update_type 3-bit EPS Update Type value
 * @return 5GS Update Type IE value (0x02=TA_UPDATING, 0x03=PERIODIC_UPDATING)
 */
uint8_t s1n2_map_eps_update_type_to_update_ie(uint8_t eps_update_type) {
	uint8_t value = eps_update_type & 0x07;
	switch (value) {
	case 3:
		return S1N2_5GS_UPDATE_TYPE_PERIODIC_UPDATING;
	default:
		return S1N2_5GS_UPDATE_TYPE_TA_UPDATING;
	}
}

/**
 * @brief Build Registration Type octet
 *
 * Constructs 5G Registration Type IE octet from type, follow-on-request,
 * and cached UE security context (KSI, TSC).
 *
 * Octet layout (TS 24.501 § 9.11.3.7):
 *   Bit 7: TSC (Type of Security Context)
 *   Bits 6-4: ngKSI
 *   Bit 3: Follow-On-Request
 *   Bits 2-0: Registration Type
 *
 * @param reg_value Registration Type (0=Initial, 1=reserved, 2=Mobility, 3=Periodic)
 * @param follow_on_request Follow-On-Request flag (0/1)
 * @param ue_map UE context with cached security info (KSI, TSC), may be NULL
 * @return 8-bit Registration Type octet
 */
uint8_t s1n2_build_registration_type_octet(uint8_t reg_value,
					   uint8_t follow_on_request,
					   const ue_id_mapping_t *ue_map) {
	uint8_t ksi = 0x07;
	uint8_t tsc = 0;
	if (ue_map) {
		if (ue_map->has_last_ngksi_5g) {
			ksi = ue_map->last_ngksi_5g & 0x07;
			tsc = ue_map->last_ngksi_tsc_5g & 0x01;
		} else if (ue_map->has_security_mode) {
			ksi = ue_map->last_ngksi & 0x07;
			tsc = (ue_map->last_ngksi_octet >> 3) & 0x01;
		}
	}
	return (uint8_t)(((tsc & 0x01) << 7) |
			((ksi & 0x07) << 4) |
			((follow_on_request & 0x01) << 3) |
			(reg_value & 0x07));
}

/**
 * @brief Append Update Type IE to 5G NAS message
 *
 * Adds Update Type IE (TS 24.501 § 9.11.3.49) to 5G NAS message.
 * Update Type indicates whether this is TA update or periodic registration.
 *
 * @param nas Output NAS message buffer
 * @param offset Current write position (updated on success)
 * @param capacity Total buffer size
 * @param value Update Type value (0x02=TA_UPDATING, 0x03=PERIODIC_UPDATING)
 * @return 0 on success, -1 on insufficient space or invalid parameters
 */
int s1n2_append_update_type(uint8_t *nas,
			    size_t *offset,
			    size_t capacity,
			    uint8_t value) {
	if (!nas || !offset) {
		return -1;
	}
	if ((*offset) + 3 > capacity) {
		LOG_ERROR("Not enough space to append 5GS update_type IE\n");
		return -1;
	}
	nas[(*offset)++] = S1N2_5GS_IEI_UPDATE_TYPE;
	nas[(*offset)++] = 0x01;
	nas[(*offset)++] = value;
	return 0;
}

/**
 * @brief Append Last Visited Registered TAI IE to 5G NAS message
 *
 * Adds Last Visited Registered TAI IE (TS 24.501 § 9.11.3.28) to message.
 * TAI (Tracking Area Identity) = PLMN (3 bytes) + TAC (2 bytes).
 *
 * If UE context has location info cached, uses cached values.
 * Otherwise, retrieves PLMN/TAC from environment variables.
 *
 * @param nas Output NAS message buffer
 * @param offset Current write position (updated on success)
 * @param capacity Total buffer size
 * @param ue_map UE context with cached TAI, may be NULL
 * @return 0 on success, -1 on insufficient space or invalid parameters
 */
int s1n2_append_last_visited_tai(uint8_t *nas,
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
		LOG_ERROR("Not enough space to append last_visited_registered_tai IE\n");
		return -1;
	}
	nas[(*offset)++] = S1N2_5GS_IEI_LAST_VISITED_TAI;
	nas[(*offset)++] = 0x06;
	memcpy(nas + *offset, plmn, 3);
	(*offset) += 3;
	nas[(*offset)++] = 0x00;
	nas[(*offset)++] = (uint8_t)((tac16 >> 8) & 0xFF);
	nas[(*offset)++] = (uint8_t)(tac16 & 0xFF);
	return 0;
}
