/**
 * @file tau/tau_request_4g_to_5g.c
 * @brief 4G TAU Request (0x48) → 5G Registration Request (mobility update)
 *
 * Phase 6 of NAS modularization.
 * Split from registration/attach_request_4g_to_5g.c.
 *
 * Handles:
 *   - Mobility / periodic registration via cached 5G-GUTI
 *   - TAU-specific IEs: update_type, last_visited_tai
 *   - PDU Session Status IE (when security context available)
 *   - Integrity protection for mobility updates
 *
 * Does NOT handle:
 *   - Initial registration / SUCI building (handled by registration module)
 *   - ESM PDN request caching (Attach Request only)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "internal/nas_module_common.h"
#include "tau/tau.h"

int tau_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                 uint8_t first_byte, size_t payload_offset,
                                 uint8_t *nas_5g, size_t *nas_5g_len,
                                 s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
	size_t nas_5g_offset = 0;

	/* EPD + Security header (plain) */
	nas_5g[nas_5g_offset++] = 0x7E;
	nas_5g[nas_5g_offset++] = 0x00;

	uint8_t protocol_discriminator = first_byte & 0x0F;
	if (protocol_discriminator == 0x06) {
		printf("[INFO] 4G NAS uses ESM protocol discriminator (0x6); generating Registration Request for 5GMM\n");
	}

	/* ============================================================
	 * Parse EPS Update Type from TAU Request
	 * ============================================================ */
	uint8_t eps_update_byte = 0;
	uint8_t eps_update_type = 0;
	uint8_t follow_on_request = 0;
	if (payload_offset < nas_4g_len) {
		eps_update_byte = nas_4g[payload_offset];
		eps_update_type = eps_update_byte & 0x07;
		follow_on_request = (eps_update_byte >> 3) & 0x01;
	}

	uint8_t registration_value = s1n2_map_eps_update_type(eps_update_type);
	printf("[INFO] ========== Converting 4G TAU Request (0x48) -> 5G Registration Update =========\n");
	printf("[INFO] EPS update type=0x%02X mapped to 5GS registration type=0x%02X (follow_on=%u)\n",
	       eps_update_type, registration_value, follow_on_request);
	fflush(stdout);

	/* Message Type: Registration Request (0x41) */
	nas_5g[nas_5g_offset++] = 0x41;

	uint8_t registration_type_octet = s1n2_build_registration_type_octet(
		registration_value, follow_on_request, ue_map);
	nas_5g[nas_5g_offset++] = registration_type_octet;

	size_t nas_capacity = (*nas_5g_len > 0) ? *nas_5g_len : 256;

	/* ============================================================
	 * 5GS Mobile Identity: use cached 5G-GUTI
	 * ============================================================ */
	bool using_cached_guti = (ue_map && ue_map->has_last_5g_guti &&
	                          ue_map->last_5g_guti_len > 0);

	const uint8_t *identity_payload = NULL;
	size_t identity_len = 0;

	if (using_cached_guti) {
		identity_payload = ue_map->last_5g_guti;
		identity_len = ue_map->last_5g_guti_len;
		printf("[INFO] Reusing cached 5G-GUTI for TAU mobility update (len=%zu)\n", identity_len);
	} else {
		/* TAU without cached GUTI is unusual; fall back to initial registration
		 * delegated to the registration module.  Log and return error. */
		printf("[ERROR] TAU Request but no cached 5G-GUTI available — cannot build mobility Registration Request\n");
		return -1;
	}

	if (identity_len == 0 || identity_len > 0xFFFF) {
		printf("[ERROR] Invalid 5GS mobile identity length=%zu\n", identity_len);
		return -1;
	}
	if (nas_5g_offset + 2 + identity_len > nas_capacity) {
		printf("[ERROR] 5G NAS buffer too small for mobile identity (need %zu, cap %zu)\n",
		       2UL + identity_len, nas_capacity - nas_5g_offset);
		return -1;
	}
	uint16_t identity_len_be = htons((uint16_t)identity_len);
	memcpy(nas_5g + nas_5g_offset, &identity_len_be, sizeof(identity_len_be));
	nas_5g_offset += 2;
	memcpy(nas_5g + nas_5g_offset, identity_payload, identity_len);
	nas_5g_offset += identity_len;

	/* ============================================================
	 * TAU-specific IEs: update_type, last_visited_tai
	 * ============================================================ */
	uint8_t update_ie_value = s1n2_map_eps_update_type_to_update_ie(eps_update_type);
	if (s1n2_append_update_type(nas_5g, &nas_5g_offset, nas_capacity,
	                            update_ie_value) == 0) {
		printf("[DEBUG] Added 5GS update_type IE (value=0x%02X)\n", update_ie_value);
	}
	if (s1n2_append_last_visited_tai(nas_5g, &nas_5g_offset, nas_capacity, ue_map) == 0) {
		printf("[DEBUG] Added last_visited_registered_tai IE (len=6)\n");
	} else {
		printf("[WARN] Could not append last_visited_registered_tai IE (missing location or buffer)\n");
	}

	/* ============================================================
	 * UE Security Capability IE
	 * ============================================================ */
	const uint8_t ue_security_payload[] = { 0xF0, 0x70, 0xF0, 0x70 };
	const size_t ue_security_ie_len = sizeof(ue_security_payload) + 2;
	if (nas_5g_offset + ue_security_ie_len > nas_capacity) {
		size_t remaining = (nas_capacity > nas_5g_offset) ? (nas_capacity - nas_5g_offset) : 0;
		printf("[ERROR] 5G NAS buffer too small for UE security capability IE (need %zu, cap %zu)\n",
		       ue_security_ie_len, remaining);
		return -1;
	}
	nas_5g[nas_5g_offset++] = 0x2E;
	nas_5g[nas_5g_offset++] = sizeof(ue_security_payload);
	memcpy(nas_5g + nas_5g_offset, ue_security_payload, sizeof(ue_security_payload));
	nas_5g_offset += sizeof(ue_security_payload);

	printf("[DEBUG] UE Security Capability IE added (5G-NEA=0x%02X, 5G-NIA=0x%02X, EEA=0x%02X, EIA=0x%02X)\n",
	       ue_security_payload[0], ue_security_payload[1],
	       ue_security_payload[2], ue_security_payload[3]);

	/* ============================================================
	 * PDU Session Status IE (mobility registrations with security context)
	 * ============================================================ */
	bool has_secure_context = (ue_map && ue_map->has_5g_nas_keys && ue_map->has_sent_smc);
	bool is_initial_registration = (registration_value == S1N2_5GS_REG_TYPE_INITIAL);
	bool can_send_pdu_status_ie = has_secure_context && !is_initial_registration;

	uint16_t pdu_session_status_mask = s1n2_build_pdu_session_status_mask(ctx, ue_map);
	if (pdu_session_status_mask) {
		if (can_send_pdu_status_ie) {
			if (s1n2_append_pdu_session_status(nas_5g, &nas_5g_offset, nas_capacity,
			                                   pdu_session_status_mask) == 0) {
				printf("[DEBUG] Added PDU Session Status IE (mask=0x%04X)\n", pdu_session_status_mask);
			} else {
				printf("[WARN] Failed to append PDU Session Status IE (mask=0x%04X)\n",
				       pdu_session_status_mask);
			}
		} else {
			printf("[TRACE] Skipped PDU Session Status IE (mask=0x%04X) because NAS is not integrity protected yet\n",
			       pdu_session_status_mask);
		}
	}

	/* ============================================================
	 * Integrity protection (for mobility/periodic registrations)
	 * ============================================================ */
	if (has_secure_context && !is_initial_registration) {
		uint8_t mac[4];
		if (s1n2_compute_5g_uplink_mac(ue_map, nas_5g, nas_5g_offset, mac) == 0) {
			size_t protected_len = nas_5g_offset + 7;
			if (protected_len > nas_capacity) {
				printf("[ERROR] Buffer too small to wrap Registration Request with security (need=%zu, cap=%zu)\n",
				       protected_len, nas_capacity);
			} else {
				memmove(nas_5g + 7, nas_5g, nas_5g_offset);
				nas_5g[0] = 0x7E;
				nas_5g[1] = 0x01;
				nas_5g[2] = mac[0];
				nas_5g[3] = mac[1];
				nas_5g[4] = mac[2];
				nas_5g[5] = mac[3];
				nas_5g[6] = (uint8_t)(ue_map->nas_ul_count_5g & 0xFF);
				nas_5g_offset = protected_len;
				ue_map->nas_ul_count_5g++;
				printf("[INFO] Mobility Registration Request integrity protected (reg_type=0x%02X, seq=0x%02X)\n",
				       registration_value, nas_5g[6]);
			}
		} else {
			printf("[WARN] Failed to compute MAC for Mobility Registration Request; sending plain\n");
		}
	} else if (has_secure_context) {
		printf("[TRACE] Leaving initial Registration Request plain despite keys (reg_type=0x%02X)\n",
		       registration_value);
	}

	*nas_5g_len = nas_5g_offset;

	/* ============================================================
	 * Logging
	 * ============================================================ */
	printf("[DEBUG] 5G Registration Request created (len=%zu, 5G-GUTI=cached)\n", *nas_5g_len);
	s1n2_dump_hex("[NAS][UL] Registration Request", nas_5g, *nas_5g_len);
	printf("[DEBUG] Cached 5G-GUTI payload (len=%u): ", ue_map ? ue_map->last_5g_guti_len : 0);
	if (ue_map) {
		for (size_t i = 0; i < ue_map->last_5g_guti_len && i < 16; ++i) {
			printf("%02X ", ue_map->last_5g_guti[i]);
		}
		if (ue_map->last_5g_guti_len > 16) printf("...");
	}
	printf("\n");
	fflush(stdout);

	return 0;
}
