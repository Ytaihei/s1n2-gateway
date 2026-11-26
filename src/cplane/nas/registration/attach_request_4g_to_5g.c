#include "s1n2_log.h"
/**
 * @file registration/attach_request_4g_to_5g.c
 * @brief 4G Attach Request (0x41/0x0C) → 5G Registration Request (0x41)
 *
 * Phase 5 of NAS modularization.
 * Extracted from nas_4g_to_5g.c.
 *
 * Handles:
 *   - Initial registration via SUCI (Attach Request 0x41 / 0x0C)
 *   - ESM PDN request caching
 *
 * TAU Request (0x48) handling has been split to tau/tau_request_4g_to_5g.c
 * in Phase 6.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "suci_utils.h"
#include "subscriber_auth.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "internal/nas_module_common.h"
#include "registration/registration.h"

int attach_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                    uint8_t first_byte, uint8_t msg_type,
                                    size_t payload_offset,
                                    uint8_t *nas_5g, size_t *nas_5g_len,
                                    s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
	size_t nas_5g_offset = 0;

	nas_5g[nas_5g_offset++] = 0x7E;
	nas_5g[nas_5g_offset++] = 0x00;

	uint8_t protocol_discriminator = first_byte & 0x0F;

	if (protocol_discriminator == 0x06) {
		LOG_INFO("4G NAS uses ESM protocol discriminator (0x6); generating Registration Request for 5GMM\n");
	}

	// ============================================================
	// 4G to 5G NAS Message Type Conversion
	// ============================================================
	uint8_t follow_on_request = 0;

	if (msg_type == 0x41 || msg_type == 0x0C) {
		LOG_INFO("Converting 4G Attach Request (0x%02X) -> 5G Registration Request (initial)\n", msg_type);
	} else {
		LOG_INFO("Converting 4G message type 0x%02X -> 5G Registration Request (initial)\n", msg_type);
	}

	uint8_t registration_value = S1N2_5GS_REG_TYPE_INITIAL;

	// Extended protocol discriminator: 5GMM
	nas_5g[nas_5g_offset++] = 0x41;  // Registration Request

	uint8_t registration_type_octet = s1n2_build_registration_type_octet(
		registration_value, follow_on_request, ue_map);
	nas_5g[nas_5g_offset++] = registration_type_octet;
	// Note: Do NOT insert a standalone ngKSI octet here.
	// Open5GS expects the 5GS mobile identity length to follow immediately
	// after the 5GS registration type for initial registration with SUCI.
	// Inserting an extra octet here shifts the decoder and causes length
	// to be read from the wrong offset (e.g., 0x07 0x00 -> 0x0700).

	size_t nas_capacity = (*nas_5g_len > 0) ? *nas_5g_len : 256;
	uint8_t suci_payload[32];
	size_t suci_payload_len = sizeof(suci_payload);
	char imsi_digits[32] = {0};
	int suci_result = -1;
	const uint8_t *mobile_identity_ptr = NULL;
	size_t mobile_identity_len = 0;

	{
		suci_builder_config_t suci_cfg;
		s1n2_init_suci_config(&suci_cfg);
		int mi_offset = s1n2_locate_eps_mobile_identity(nas_4g, nas_4g_len, payload_offset,
					   &mobile_identity_ptr, &mobile_identity_len);
		if (mi_offset < 0) {
			mi_offset = s1n2_locate_eps_mobile_identity(nas_4g, nas_4g_len, 0,
					   &mobile_identity_ptr, &mobile_identity_len);
		}
		if (mi_offset >= 0) {
			suci_payload_len = sizeof(suci_payload);
			suci_result = suci_build_from_eps_mobile_identity(mobile_identity_ptr, mobile_identity_len,
					  &suci_cfg, suci_payload, &suci_payload_len,
					  imsi_digits, sizeof(imsi_digits));
			LOG_DEBUG("EPS Mobile Identity located at offset %d (len=%zu)\n", mi_offset, mobile_identity_len);
		}
		if (suci_result != 0) {
			const char *fallback_imsi = s1n2_get_fallback_imsi();
			if (fallback_imsi && *fallback_imsi) {
				char fallback_digits[32] = {0};
				s1n2_copy_digits(fallback_imsi, fallback_digits, sizeof(fallback_digits));
				size_t fallback_len = strlen(fallback_digits);
				if (fallback_len >= 5) {
					suci_payload_len = sizeof(suci_payload);
					suci_result = suci_build_from_imsi_digits(fallback_digits, fallback_len,
					  &suci_cfg, suci_payload, &suci_payload_len);
					if (suci_result == 0) {
						strncpy(imsi_digits, fallback_digits, sizeof(imsi_digits) - 1);
						imsi_digits[sizeof(imsi_digits) - 1] = '\0';

					}
				}
			}
		}
		if (suci_result != 0) {

			return -1;
		}
	}

	const uint8_t *identity_payload = suci_payload;
	size_t identity_len = suci_payload_len;
	if (identity_len == 0 || identity_len > 0xFFFF) {
		LOG_ERROR("Invalid 5GS mobile identity length=%zu\n", identity_len);
		return -1;
	}
	if (nas_5g_offset + 2 + identity_len > nas_capacity) {
		LOG_ERROR("5G NAS buffer too small for mobile identity (need %zu, cap %zu)\n",
			   2UL + identity_len, nas_capacity - nas_5g_offset);
		return -1;
	}
	uint16_t identity_len_be = htons((uint16_t)identity_len);
	memcpy(nas_5g + nas_5g_offset, &identity_len_be, sizeof(identity_len_be));
	nas_5g_offset += 2;
	memcpy(nas_5g + nas_5g_offset, identity_payload, identity_len);
	nas_5g_offset += identity_len;

	const uint8_t ue_security_payload[] = {
		0xF0,
		0x70,
		0xF0,
		0x70
	};
	const size_t ue_security_ie_len = sizeof(ue_security_payload) + 2;
	if (nas_5g_offset + ue_security_ie_len > nas_capacity) {
		size_t remaining_capacity = (nas_capacity > nas_5g_offset) ? (nas_capacity - nas_5g_offset) : 0;
		LOG_ERROR("5G NAS buffer too small for UE security capability IE (need %zu, cap %zu)\n",
			   ue_security_ie_len, remaining_capacity);
		return -1;
	}

	nas_5g[nas_5g_offset++] = 0x2E;
	nas_5g[nas_5g_offset++] = sizeof(ue_security_payload);
	memcpy(nas_5g + nas_5g_offset, ue_security_payload, sizeof(ue_security_payload));
	nas_5g_offset += sizeof(ue_security_payload);

	/* Initial registration: no PDU session status, no integrity protection */

	*nas_5g_len = nas_5g_offset;

	s1n2_dump_hex("[NAS][UL] Registration Request", nas_5g, *nas_5g_len);

	// Extract and cache ESM message container (PDN connectivity request) from 4G Attach Request
	// TS 24.301: Attach Request mandatory IE includes ESM message container (IEI=0x78)
	// Successful MME traces show ESM1 (UE's PDN request) piggybacked in Attach Accept
	if (ue_map && (msg_type == 0x41 || msg_type == 0x0C)) {
		// Search for ESM message container IEI (0x78) in 4G Attach Request
		bool found_esm = false;
		for (size_t search_off = payload_offset; search_off + 2 < nas_4g_len; ++search_off) {
			if (nas_4g[search_off] == 0x78) {
				// Found ESM container IEI
				uint16_t esm_len_be;
				if (search_off + 3 <= nas_4g_len) {
					memcpy(&esm_len_be, &nas_4g[search_off + 1], 2);
					uint16_t esm_len = ntohs(esm_len_be);
					if (esm_len > 0 && esm_len <= 64 && search_off + 3 + esm_len <= nas_4g_len) {
						// Valid ESM container found
						memcpy(ue_map->cached_esm_pdn_request, &nas_4g[search_off + 3], esm_len);
						ue_map->cached_esm_pdn_request_len = (uint8_t)esm_len;
						ue_map->has_cached_esm_pdn_request = true;
						found_esm = true;
						LOG_INFO("Cached ESM PDN connectivity request from Attach Request (len=%u)\n", esm_len);

						break;
					}
				}
			}
		}
		if (!found_esm) {
			LOG_DEBUG("No ESM message container (IEI=0x78) found in 4G Attach Request\n");
		}
		if (found_esm && ue_map) {
			const uint8_t *esm_buf = ue_map->cached_esm_pdn_request;
			size_t esm_len = ue_map->cached_esm_pdn_request_len;
			const uint8_t *pco_ptr = NULL;
			uint8_t pco_len = 0;
			for (size_t scan = 0; scan + 1 < esm_len; ++scan) {
				if (esm_buf[scan] == 0x27) {
					uint8_t len = esm_buf[scan + 1];
					if (scan + 2 + len <= esm_len) {
						pco_ptr = &esm_buf[scan + 2];
						pco_len = len;
					}
					break;
				}
			}
			if (pco_ptr && pco_len > 0) {
				s1n2_log_pco_entries("[UE->S1] Cached PDN request PCO", pco_ptr, pco_len);
			} else {
				LOG_TRACE("[UE->S1] Cached PDN request has no PCO IE\n");
			}
		}
	}

	return 0;
}
