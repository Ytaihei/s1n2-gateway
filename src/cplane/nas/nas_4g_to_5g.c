/**
 * @file nas_4g_to_5g.c
 * @brief Uplink NAS dispatcher: 4G (EPS) → 5G (5GS) message routing
 *
 * Dispatcher that parses 4G NAS headers and delegates to per-module
 * converters (auth, security, registration, tau).
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_conversion_internal.h"
#include "auth/auth.h"
#include "security/security.h"
#include "registration/registration.h"
#include "tau/tau.h"

int convert_4g_nas_to_5g(s1n2_context_t *ctx, ue_id_mapping_t *ue_map,
						 uint8_t *nas_4g, size_t nas_4g_len,
						 uint8_t *nas_5g, size_t *nas_5g_len) {
	if (!nas_4g || !nas_5g || !nas_5g_len || nas_4g_len == 0) {
		return -1;
	}

	printf("[DEBUG] Converting 4G NAS-PDU to 5G (input len=%zu)\n", nas_4g_len);

	printf("[DEBUG] 4G NAS-PDU bytes: ");
	for (size_t i = 0; i < nas_4g_len && i < 16; i++) {
		printf("%02X ", nas_4g[i]);
	}
	if (nas_4g_len > 16) printf("...");
	printf("\n");

	uint8_t first_byte = nas_4g[0];
	uint8_t second_byte = (nas_4g_len > 1) ? nas_4g[1] : 0x00;

	printf("[DEBUG] 4G NAS: first_byte=0x%02X, second_byte=0x%02X\n", first_byte, second_byte);

	if (first_byte == 0x0C && second_byte == 0x07) {
		printf("[INFO] Detected 4G Attach Request (0x0C 0x07 format)\n");
	} else {
		uint8_t security_header = (first_byte >> 4) & 0x0F;
		uint8_t protocol_discriminator = first_byte & 0x0F;

		printf("[DEBUG] Standard 4G NAS: security_header=0x%X, protocol_discriminator=0x%X\n",
			   security_header, protocol_discriminator);

		if (protocol_discriminator != 0x07 && protocol_discriminator != 0x06) {
			printf("[WARN] Not a 4G EMM/ESM message (PD=0x%X), cannot convert\n", protocol_discriminator);
			return -1;
		}

		if (protocol_discriminator == 0x06) {
			printf("[INFO] Detected 4G ESM message (PD=0x6), converting to 5G Registration Request\n");
		}
	}

	uint8_t msg_type = 0x00;
	size_t payload_offset = 1;

	if (first_byte == 0x0C && second_byte == 0x07) {
		msg_type = first_byte;
		payload_offset = 2;
		printf("[DEBUG] 4G Attach Request: msg_type=0x%02X, offset=%zu\n", msg_type, payload_offset);
	} else {
		uint8_t security_header = (first_byte >> 4) & 0x0F;

		if (security_header == 0x00 || security_header == 0x01) {
			if (nas_4g_len > 1) {
				msg_type = nas_4g[1];
				payload_offset = 2;
			}
		} else if (security_header == 0x07) {
			printf("[INFO] Processing security header type 0x7 (Attach Request)\n");
			if (nas_4g_len > 1) {
				msg_type = nas_4g[1];
				payload_offset = 2;
			}
		} else {
			printf("[WARN] Secured NAS message (security=0x%X) - attempting protected conversion\n", security_header);
			if (nas_4g_len <= 7) {
				printf("[ERROR] Secured NAS message too short for payload (len=%zu)\n", nas_4g_len);
				return -1;
			}
			const size_t inner_header_offset = 6;
			uint8_t inner_first_octet = nas_4g[inner_header_offset];
			uint8_t inner_security_header = (inner_first_octet >> 4) & 0x0F;
			uint8_t inner_protocol_discriminator = inner_first_octet & 0x0F;
			printf("[DEBUG] Inner NAS header: security=0x%X, protocol=0x%X\n",
				   inner_security_header, inner_protocol_discriminator);
			if (inner_protocol_discriminator != 0x07) {
				printf("[WARN] Unexpected protocol discriminator inside protected NAS (pd=0x%X)\n",
					   inner_protocol_discriminator);
			}
			if (inner_security_header != 0x00 && inner_security_header != 0x01) {
				printf("[DEBUG] Inner NAS payload itself uses security header 0x%X\n",
					   inner_security_header);
			}
			size_t message_type_offset = inner_header_offset + 1;
			if (message_type_offset >= nas_4g_len) {
				printf("[ERROR] Secured NAS message missing message type (len=%zu)\n", nas_4g_len);
				return -1;
			}
			msg_type = nas_4g[message_type_offset];
			payload_offset = message_type_offset + 1;
		}
	}

	/* ---- Cache UE Security Capability IE (0x5E) ---- */
	cache_ue_security_capability(ue_map, nas_4g, nas_4g_len, payload_offset);

	printf("[DEBUG] 4G Message Type: 0x%02X\n", msg_type);

	// ===== Registration Module (Phase 5 extraction) =====
	// 0x43 = Attach Complete → Registration Complete
	if (msg_type == 0x43) {
		return attach_complete_convert_4g_to_5g(nas_5g, nas_5g_len, ue_map);
	}

	// ===== Security Mode Module (Phase 3 extraction) =====
	// 0x5E = Security Mode Complete
	if (msg_type == 0x5E) {
		return smc_complete_convert_4g_to_5g(nas_4g, nas_4g_len, first_byte, msg_type,
		                                     payload_offset, nas_5g, nas_5g_len, ctx, ue_map);
	}

	// ===== Authentication Module (Phase 2 extraction) =====
	// 0x5C = Authentication Failure, 0x53 = Authentication Response
	if (msg_type == 0x5C) {
		return auth_failure_convert_4g_to_5g(nas_4g, nas_4g_len, payload_offset,
		                                     nas_5g, nas_5g_len, ctx, ue_map);
	}
	if (msg_type == 0x53) {
		return auth_response_convert_4g_to_5g(nas_4g, nas_4g_len, payload_offset,
		                                      nas_5g, nas_5g_len, ctx, ue_map);
	}

	// ===== TAU Module (Phase 6 extraction) =====
	// 0x48 = TAU Request → 5G Registration Request (mobility update)
	if (msg_type == 0x48) {
		return tau_request_convert_4g_to_5g(nas_4g, nas_4g_len, first_byte,
		                                    payload_offset, nas_5g, nas_5g_len, ctx, ue_map);
	}

	// ===== Registration Module (Phase 5 extraction) =====
	// 0x41/0x0C = Attach Request → 5G Registration Request (initial)
	return attach_request_convert_4g_to_5g(nas_4g, nas_4g_len, first_byte, msg_type,
	                                       payload_offset, nas_5g, nas_5g_len, ctx, ue_map);
}
