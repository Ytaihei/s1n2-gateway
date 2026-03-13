/**
 * @file registration/registration_helpers.c
 * @brief Identity helper functions for Registration / Attach module
 *
 * Phase 5 of NAS modularization.
 * Extracted from nas_4g_to_5g_helpers.c.
 *
 * Functions:
 *   - s1n2_locate_eps_mobile_identity()  — scans 4G NAS for BCD-encoded identity
 *   - s1n2_get_fallback_imsi()           — retrieves IMSI from environment
 *   - s1n2_extract_imsi_from_5g_registration_request() — decodes SUCI IMSI
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_module_common.h"
#include "internal/nas_conversion_internal.h"
#include "registration/registration.h"

/* ================================================================
 * EPS Mobile Identity locator
 * ================================================================ */

int s1n2_locate_eps_mobile_identity(const uint8_t *nas, size_t nas_len,
				    size_t start_offset,
				    const uint8_t **value_ptr,
				    size_t *value_len) {
	if (!nas || !value_ptr || !value_len) {
		return -1;
	}

	for (size_t offset = start_offset; offset + 1 < nas_len; ++offset) {
		uint8_t len = nas[offset];
		if (len < 3 || len > 11) {
			continue;
		}
		if (offset + 1 + len > nas_len) {
			continue;
		}

		const uint8_t *candidate = nas + offset + 1;
		uint8_t first = candidate[0];
		/* EPS Mobile Identity first byte: bits[2:0] = identity type (001 = IMSI) */
		if ((first & 0x07) != 0x01) {
			continue;
		}

		bool digits_ok = true;
		for (size_t i = 1; i < len; ++i) {
			uint8_t b = candidate[i];
			uint8_t low = b & 0x0F;
			uint8_t high = (b >> 4) & 0x0F;
			if ((low > 9 && low != 0xF) || (high > 9 && high != 0xF)) {
				digits_ok = false;
				break;
			}
		}
		if (!digits_ok) {
			continue;
		}

		*value_ptr = candidate;
		*value_len = len;
		return (int)offset;
	}

	return -1;
}

/* ================================================================
 * Fallback IMSI from environment
 * ================================================================ */

const char *s1n2_get_fallback_imsi(void) {
	const char *candidates[] = {
		"S1N2_FALLBACK_IMSI",
		"UE1_IMSI",
		"UE_IMSI",
		"IMSI",
		NULL
	};

	for (size_t i = 0; candidates[i]; ++i) {
		const char *val = getenv(candidates[i]);
		if (val && *val) {
			return val;
		}
	}
	return NULL;
}

/* ================================================================
 * IMSI extraction from 5G Registration Request (SUCI)
 * ================================================================ */

int s1n2_extract_imsi_from_5g_registration_request(const uint8_t *nas_pdu, size_t nas_len, char *imsi_out, size_t imsi_len) {
	if (!nas_pdu || nas_len < 10 || !imsi_out || imsi_len < 16) {
		return -1;
	}

	if (nas_pdu[0] != 0x7E || nas_pdu[2] != 0x41) {
		printf("[DEBUG] Not a 5G Registration Request (EPD=0x%02X, Type=0x%02X)\n",
			   nas_pdu[0], nas_len > 2 ? nas_pdu[2] : 0);
		return -1;
	}

	size_t offset = 4;

	if (offset + 2 > nas_len) {
		printf("[DEBUG] NAS-PDU too short for Mobile Identity\n");
		return -1;
	}

	uint16_t identity_len = (nas_pdu[offset] << 8) | nas_pdu[offset + 1];
	offset += 2;

	if (offset + identity_len > nas_len) {
		printf("[DEBUG] Mobile Identity length mismatch (len=%u, available=%zu)\n",
			   identity_len, nas_len - offset);
		return -1;
	}

	size_t identity_end = offset + identity_len;

	uint8_t identity_type = nas_pdu[offset] & 0x07;

	if (identity_type != 0x01) {
		printf("[DEBUG] Mobile Identity is not SUCI (type=%u)\n", identity_type);
		return -1;
	}

	uint8_t supi_format = (nas_pdu[offset] >> 4) & 0x07;
	if (supi_format != 0x00) {
		printf("[DEBUG] SUPI format is not IMSI (format=%u)\n", supi_format);
		return -1;
	}

	offset++;

	if (offset + 3 > nas_len) {
		printf("[DEBUG] PLMN truncated\n");
		return -1;
	}

	char mcc[4] = {0};
	char mnc[4] = {0};
	mcc[0] = '0' + (nas_pdu[offset] & 0x0F);
	mcc[1] = '0' + ((nas_pdu[offset] >> 4) & 0x0F);
	mcc[2] = '0' + (nas_pdu[offset + 1] & 0x0F);
	mnc[0] = '0' + (nas_pdu[offset + 2] & 0x0F);
	mnc[1] = '0' + ((nas_pdu[offset + 2] >> 4) & 0x0F);
	uint8_t mnc3 = (nas_pdu[offset + 1] >> 4) & 0x0F;
	if (mnc3 != 0x0F) {
		mnc[2] = '0' + mnc3;
		mnc[3] = '\0';
	} else {
		mnc[2] = '\0';
	}
	offset += 3;

	offset += 4;

	char imsi_str[16] = {0};
	int imsi_pos = 0;

	imsi_pos += snprintf(imsi_str + imsi_pos, sizeof(imsi_str) - imsi_pos, "%s%s", mcc, mnc);

	while (offset < identity_end && imsi_pos < 15) {
		uint8_t digit1 = nas_pdu[offset] & 0x0F;
		uint8_t digit2 = (nas_pdu[offset] >> 4) & 0x0F;

		if (digit1 != 0x0F && imsi_pos < 15) {
			imsi_str[imsi_pos++] = '0' + digit1;
		}
		if (digit2 != 0x0F && imsi_pos < 15) {
			imsi_str[imsi_pos++] = '0' + digit2;
		}
		offset++;
	}

	imsi_str[imsi_pos] = '\0';

	if (imsi_pos >= 10) {
		strncpy(imsi_out, imsi_str, imsi_len - 1);
		imsi_out[imsi_len - 1] = '\0';
		printf("[INFO] Successfully extracted IMSI: %s\n", imsi_out);
		return 0;
	}

	printf("[DEBUG] Extracted IMSI too short (len=%d): %s\n", imsi_pos, imsi_str);
	return -1;
}

/* ================================================================
 * Registration Accept artifact caching
 * ================================================================
 * Moved from nas_5g_to_4g_helpers.c during Phase 7 cleanup.
 * Caches 5G-GUTI and registration result from Registration Accept.
 */

void s1n2_cache_registration_accept_artifacts(ue_id_mapping_t *ue_map,
					      const uint8_t *msg,
					      size_t msg_len) {
	if (!ue_map || !msg || msg_len < 4) {
		return;
	}
	s1n2_dump_hex("[NAS][DL] Registration Accept (raw)", msg, msg_len);
	size_t pos = 3;
	if (pos >= msg_len) {
		return;
	}
	uint8_t reg_len = msg[pos++];
	if (pos + reg_len > msg_len) {
		return;
	}
	if (reg_len > 0) {
		s1n2_context_cache_registration_result(ue_map, msg + pos, reg_len);
	}
	pos += reg_len;
	for (size_t i = pos; i + 3 < msg_len; ++i) {
		if (msg[i] != S1N2_5GS_IEI_5G_GUTI) {
			continue;
		}
		if (i + 3 >= msg_len) {
			break;
		}
		uint16_t guti_len = ((uint16_t)msg[i + 1] << 8) | msg[i + 2];
		size_t value_pos = i + 3;
		if (value_pos + guti_len > msg_len) {
			printf("[WARN] 5G-GUTI IE length exceeds NAS payload (len=%u, remain=%zu)\n",
				       guti_len, msg_len - value_pos);
			break;
		}
		s1n2_context_cache_5g_guti(ue_map, msg + value_pos, guti_len);
		break;
	}
}

/* ================================================================
 * UE Security Capability caching (IEI 0x5E)
 * ================================================================ */

void cache_ue_security_capability(ue_id_mapping_t *ue_map,
                                  const uint8_t *nas_4g, size_t nas_4g_len,
                                  size_t payload_offset) {
	if (!ue_map || !nas_4g) return;

	uint8_t cached_cap[S1N2_MAX_UE_SECURITY_CAP_LEN] = {0};
	uint8_t cached_cap_len = 0;

	for (size_t i = payload_offset; i + 1 < nas_4g_len; ++i) {
		if (nas_4g[i] != 0x5E) continue;

		uint8_t len = nas_4g[i + 1];
		if (len == 0) {
			printf("[WARN] UE security capability IE length is zero (offset=%zu)\n", i);
			break;
		}
		size_t value_pos = i + 2;
		if (value_pos + len > nas_4g_len) {
			printf("[WARN] UE security capability IE truncated (len=%u, offset=%zu, nas_len=%zu)\n",
			       len, i, nas_4g_len);
			break;
		}
		size_t copy = len;
		if (copy > S1N2_MAX_UE_SECURITY_CAP_LEN) {
			printf("[WARN] UE security capability length %u exceeds cache limit %d, truncating\n",
			       len, S1N2_MAX_UE_SECURITY_CAP_LEN);
			copy = S1N2_MAX_UE_SECURITY_CAP_LEN;
		}
		memcpy(cached_cap, nas_4g + value_pos, copy);
		cached_cap_len = (uint8_t)copy;
		printf("[DEBUG] Found UE security capability IE (raw_len=%u, stored_len=%zu)\n", len, copy);
		break;
	}

	if (cached_cap_len > 0) {
		size_t store_len = cached_cap_len;
		if (store_len > S1N2_MAX_UE_SECURITY_CAP_LEN)
			store_len = S1N2_MAX_UE_SECURITY_CAP_LEN;
		memcpy(ue_map->cached_ue_security_cap, cached_cap, store_len);
		if (store_len < S1N2_MAX_UE_SECURITY_CAP_LEN)
			memset(ue_map->cached_ue_security_cap + store_len, 0,
			       S1N2_MAX_UE_SECURITY_CAP_LEN - store_len);
		ue_map->cached_ue_security_cap_len = (uint8_t)store_len;
		ue_map->has_cached_ue_security_cap = true;
		ue_map->last_update = time(NULL);
		printf("[INFO] Cached UE security capability for UE mapping (len=%zu)\n", store_len);
	}
}
