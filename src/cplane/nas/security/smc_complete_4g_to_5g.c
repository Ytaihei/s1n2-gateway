#include "s1n2_log.h"
/**
 * @file security/smc_complete_4g_to_5g.c
 * @brief 4G Security Mode Complete → 5G Security Mode Complete conversion
 *
 * Extracted from nas_4g_to_5g.c during Phase 3 NAS modularization.
 *
 * Converts 4G Security Mode Complete (MT=0x5E) to 5G:
 *   - Parses 4G SMC Complete IEs (IMEISV, UE security capability, etc.)
 *   - Remaps IMEISV IEI (0x23 → 0x77 TLV-E)
 *   - Appends NAS message container (IEI 0x71) with piggybacked Registration Request
 *   - Computes 5G integrity MAC (AES-CMAC)
 *   - Derives KeNB from KASME (for Initial Context Setup Request)
 *
 * @warning Security-critical ordering:
 *   1. MAC computed BEFORE UL COUNT increment
 *   2. UL COUNT incremented AFTER MAC computation
 *   3. KeNB derived AFTER SMC Complete (uses KASME + UL COUNT)
 *   4. Registration Request piggybacking MUST be preserved (IEI 0x71)
 *
 * @see 3GPP TS 24.501 § 8.2.28 (Security mode complete)
 * @see 3GPP TS 33.401 A.3 (KeNB derivation)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "security/security.h"

int smc_complete_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                  uint8_t first_byte, uint8_t msg_type,
                                  size_t payload_offset,
                                  uint8_t *nas_5g, size_t *nas_5g_len,
                                  s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
	LOG_INFO("Converting 4G Security Mode Complete (0x5E) -> 5G Security Mode Complete (0x5E)\n");

	size_t offset = payload_offset;
	uint8_t extras[256];
	size_t extras_len = 0;

	bool imeisv_present = false;
	uint8_t imeisv_len = 0;

	bool additional_present = false;
	uint8_t additional_value = 0;

	bool ue_sec_cap_from_msg = false;
	uint8_t ue_sec_cap_eutra[4] = {0};
	uint8_t ue_sec_cap_eutra_len = 0;

	while (offset < nas_4g_len) {
		uint8_t iei = nas_4g[offset++];

		if ((iei & 0xF0) == 0xE0) {
			if (extras_len < sizeof(extras)) {
				extras[extras_len++] = iei;
			}
			continue;
		}

		if (offset >= nas_4g_len) {
			s1n2_log_security_mode_result("uplink", false, first_byte & 0x0F, msg_type,
										  "unexpected end of NAS while parsing IE");
			return -1;
		}

		uint8_t len = nas_4g[offset++];
		if (offset + len > nas_4g_len) {
			s1n2_log_security_mode_result("uplink", false, first_byte & 0x0F, msg_type,
										  "IE length exceeds remaining NAS payload");
			return -1;
		}

		const uint8_t *val = &nas_4g[offset];

		if (iei == 0x53) {
			size_t copy = len;
			if (copy > sizeof(ue_sec_cap_eutra)) copy = sizeof(ue_sec_cap_eutra);
			memcpy(ue_sec_cap_eutra, val, copy);
			ue_sec_cap_eutra_len = (uint8_t)copy;
			ue_sec_cap_from_msg = true;
		} else if (iei == 0x23) {
			imeisv_len = len;
			imeisv_present = true;
			if (extras_len + 3 + len <= sizeof(extras)) {
				extras[extras_len++] = 0x77;
				extras[extras_len++] = 0x00;
				extras[extras_len++] = len;
				memcpy(extras + extras_len, val, len);
				extras_len += len;

			} else {

			}
		} else if (iei == 0x36) {
			additional_present = len > 0;
			if (len > 0) {
				additional_value = val[0];
			}
			if (extras_len + 2 + len <= sizeof(extras)) {
				extras[extras_len++] = iei;
				extras[extras_len++] = len;
				memcpy(extras + extras_len, val, len);
				extras_len += len;
			} else {
				LOG_WARN("Insufficient buffer to copy Additional security info IE\n");
			}
		} else {
			if (extras_len + 2 + len <= sizeof(extras)) {
				extras[extras_len++] = iei;
				extras[extras_len++] = len;
				memcpy(extras + extras_len, val, len);
				extras_len += len;
			} else {
				LOG_WARN("Dropping unsupported IEI 0x%02X due to buffer limit\n", iei);
			}
		}

		offset += len;
	}

	ue_id_mapping_t *security_map = ue_map;
	if ((!security_map || !security_map->has_security_mode) && ctx) {
		ue_id_mapping_t *recent = s1n2_context_find_recent_security(ctx);
		if (recent && recent->has_security_mode) {
			security_map = recent;
		}
	}
	if (!security_map && ctx) {
		security_map = s1n2_context_find_recent_security(ctx);
	}

	uint8_t ngksi_octet = 0x00;
	if (security_map && security_map->has_security_mode) {
		ngksi_octet = security_map->last_ngksi_octet;
		security_map->last_update = time(NULL);
	} else if (security_map) {
		LOG_WARN("UE mapping found but no cached security mode context yet\n");
	} else {
		LOG_WARN("No cached security mode context found for Security Mode Complete conversion\n");
	}

	uint8_t ue_cap_buf[8] = {0};
	uint8_t ue_cap_len = 0;
	uint8_t eps_cap_buf[S1N2_MAX_UE_SECURITY_CAP_LEN] = {0};
	uint8_t eps_cap_len = 0;
	if (security_map && security_map->has_cached_ue_security_cap_5g &&
		security_map->cached_ue_security_cap_5g_len > 0) {
		ue_cap_len = security_map->cached_ue_security_cap_5g_len;
		if (ue_cap_len > sizeof(ue_cap_buf)) ue_cap_len = sizeof(ue_cap_buf);
		memcpy(ue_cap_buf, security_map->cached_ue_security_cap_5g, ue_cap_len);
	} else if (security_map && security_map->has_cached_ue_security_cap &&
		security_map->cached_ue_security_cap_len > 0) {
		ue_cap_len = security_map->cached_ue_security_cap_len;
		if (ue_cap_len > sizeof(ue_cap_buf)) ue_cap_len = sizeof(ue_cap_buf);
		memcpy(ue_cap_buf, security_map->cached_ue_security_cap, ue_cap_len);
	}

	if (ue_sec_cap_from_msg) {
		if (ue_cap_len >= 4) {
			if (ue_sec_cap_eutra_len > 0) {
				ue_cap_buf[2] = ue_sec_cap_eutra[0];
			}
			if (ue_sec_cap_eutra_len > 1) {
				ue_cap_buf[3] = ue_sec_cap_eutra[1];
			}
		} else if (ue_cap_len == 0) {
			ue_cap_len = 4;
			memset(ue_cap_buf, 0, ue_cap_len);
			ue_cap_buf[2] = (ue_sec_cap_eutra_len > 0) ? ue_sec_cap_eutra[0] : 0x00;
			ue_cap_buf[3] = (ue_sec_cap_eutra_len > 1) ? ue_sec_cap_eutra[1] : 0x00;
		}

		eps_cap_len = ue_sec_cap_eutra_len;
		if (eps_cap_len > sizeof(eps_cap_buf)) {
			eps_cap_len = sizeof(eps_cap_buf);
		}
		memcpy(eps_cap_buf, ue_sec_cap_eutra, eps_cap_len);
	} else if (security_map && security_map->has_cached_ue_security_cap &&
		   security_map->cached_ue_security_cap_len > 0) {
		eps_cap_len = security_map->cached_ue_security_cap_len;
		if (eps_cap_len > sizeof(eps_cap_buf)) {
			eps_cap_len = sizeof(eps_cap_buf);
		}
		memcpy(eps_cap_buf, security_map->cached_ue_security_cap, eps_cap_len);
	}

	size_t out = 0;
	if (*nas_5g_len < 4) {
		s1n2_log_security_mode_result("uplink", false, first_byte & 0x0F, msg_type,
									  "output buffer too small for header");
		return -1;
	}

	nas_5g[out++] = 0x7E;
	nas_5g[out++] = 0x00;
	nas_5g[out++] = 0x5E;

	uint8_t selected_alg_5g = 0x00;
	if (security_map && security_map->has_selected_alg_5g) {
		selected_alg_5g = security_map->selected_alg_5g;
		LOG_DEBUG("Using cached 5G NAS security algorithms octet: 0x%02X\n",
			selected_alg_5g);
	} else if (security_map && security_map->has_security_mode) {
		uint8_t selected_alg_4g = security_map->selected_nas_security_alg;
		uint8_t eea = (selected_alg_4g >> 4) & 0x07;
		uint8_t eia_val = selected_alg_4g & 0x07;
		selected_alg_5g = (uint8_t)(((eea & 0x0F) << 4) | (eia_val & 0x0F));
		security_map->selected_alg_5g = selected_alg_5g;
		security_map->has_selected_alg_5g = true;
		LOG_WARN("No cached 5G NAS algorithm octet; deriving from 4G selection (4G=0x%02X -> 5G=0x%02X)\n",
			selected_alg_4g, selected_alg_5g);
	} else {
		LOG_WARN("Unable to determine 5G NAS security algorithms octet for cache update\n");
		if (security_map) {
			security_map->has_selected_alg_5g = false;
		}
	}

	if (out > *nas_5g_len) {
		s1n2_log_security_mode_result("uplink", false, first_byte & 0x0F, msg_type,
			      "output buffer too small for mandatory fields");
		return -1;
	}

	if (security_map) {
		if (ue_cap_len > 0) {
			size_t cap5_copy = ue_cap_len;
			if (cap5_copy > sizeof(security_map->cached_ue_security_cap_5g)) {
				cap5_copy = sizeof(security_map->cached_ue_security_cap_5g);
			}
			memcpy(security_map->cached_ue_security_cap_5g, ue_cap_buf, cap5_copy);
			if (cap5_copy < sizeof(security_map->cached_ue_security_cap_5g)) {
				memset(security_map->cached_ue_security_cap_5g + cap5_copy, 0,
				       sizeof(security_map->cached_ue_security_cap_5g) - cap5_copy);
			}
			security_map->cached_ue_security_cap_5g_len = (uint8_t)cap5_copy;
			security_map->has_cached_ue_security_cap_5g = true;
		}

		if (ue_sec_cap_from_msg && ue_sec_cap_eutra_len > 0) {
			size_t eps_copy = ue_sec_cap_eutra_len;
			if (eps_copy > sizeof(security_map->cached_ue_security_cap)) {
				eps_copy = sizeof(security_map->cached_ue_security_cap);
			}
			memcpy(security_map->cached_ue_security_cap, ue_sec_cap_eutra, eps_copy);
			if (eps_copy < sizeof(security_map->cached_ue_security_cap)) {
				memset(security_map->cached_ue_security_cap + eps_copy, 0,
				       sizeof(security_map->cached_ue_security_cap) - eps_copy);
			}
			security_map->cached_ue_security_cap_len = (uint8_t)eps_copy;
			security_map->has_cached_ue_security_cap = true;
		}

		if (additional_present) {
			security_map->additional_security_info_present = true;
			security_map->additional_security_info = additional_value;
		}
	}

	// Add NAS message container IE (IEI 0x71) with cached Registration Request
	// 3GPP TS 24.501 § 8.2.28 Security mode complete - Optional IEs
	// § 9.11.3.24 NAS message container - TLV format (IEI=0x71, 2-byte length)
	if (security_map && security_map->cached_reg_req_len > 0) {
		// Calculate required space: IEI (1 byte) + Length (2 bytes) + Container data
		size_t container_ie_size = 1 + 2 + security_map->cached_reg_req_len;
		if (extras_len + container_ie_size <= sizeof(extras)) {
			// IEI 0x71 (1 byte for TLV format)
			extras[extras_len++] = 0x71;

			// Length (2 bytes, big-endian) - total length of container contents
			uint16_t container_len = (uint16_t)security_map->cached_reg_req_len;
			extras[extras_len++] = (uint8_t)(container_len >> 8);   // MSB
			extras[extras_len++] = (uint8_t)(container_len & 0xFF); // LSB

			// Copy cached Registration Request into container
			memcpy(extras + extras_len, security_map->cached_registration_request,
			       security_map->cached_reg_req_len);
			extras_len += security_map->cached_reg_req_len;

			LOG_INFO("★ Added NAS message container IE (IEI 0x71) with piggybacked Registration Request (len=%d) ★\n",
			       security_map->cached_reg_req_len);
			LOG_DEBUG("Container format: IEI=0x71, Len=0x%04x (%d bytes), Data=%d bytes\n",
			       container_len, container_len, security_map->cached_reg_req_len);

		} else {
			LOG_WARN("Insufficient buffer space for NAS message container, skipping piggybacking\n");

		}
	}

	LOG_TRACE("Before extras copy: out=%zu, extras_len=%zu, *nas_5g_len=%zu\n",
	       out, extras_len, *nas_5g_len);

	if (extras_len > 0) {
		if (out + extras_len > *nas_5g_len) {
			s1n2_log_security_mode_result("uplink", false, first_byte & 0x0F, msg_type,
										  "optional IE overflow");
			return -1;
		}
		memcpy(nas_5g + out, extras, extras_len);
		out += extras_len;
	}

	LOG_TRACE("After extras copy: out=%zu\n", out);

	// At this point, nas_5g[0..out-1] contains the complete plain 5G NAS message
	// Now add 5G Integrity Protection if security context is available

	LOG_TRACE("Checking Integrity Protection: security_map=%p, has_nas_keys=%d\n",
	       (void*)security_map, security_map ? security_map->has_nas_keys : -1);

	if (security_map && security_map->has_5g_nas_keys) {
		uint8_t mac[4];

		// Compute MAC for the complete plain NAS message (inner, without security header)
		if (s1n2_compute_5g_uplink_mac(security_map, nas_5g, out, mac) == 0) {
			// Build 5G Security Protected NAS (Integrity protected with new 5GS security context)
			// Format: [EPD=0x7E][SecHdr=0x03][MAC(4)][SEQ(1)][Plain 5G NAS (starts with 0x7E 0x00 ...)]

			uint8_t seq = (uint8_t)(((ue_id_mapping_t*)security_map)->nas_ul_count_5g & 0xFF);
			size_t protected_len = 2 /*EPD+SecHdr*/ + 4 /*MAC*/ + 1 /*SEQ*/ + out;

			if (*nas_5g_len < protected_len) {
				LOG_ERROR("Output buffer too small for protected 5G NAS (need %zu, have %zu)\n",
					   protected_len, *nas_5g_len);
				return -1;
			}

			// Assemble into a temporary buffer to avoid overlap
			uint8_t tmp[1024];
			if (protected_len > sizeof(tmp)) {
				LOG_ERROR("Temporary buffer too small for protected NAS (need %zu)\n", protected_len);
				return -1;
			}

			size_t off = 0;
			tmp[off++] = 0x7E;     // Extended protocol discriminator (5GMM)
			tmp[off++] = 0x03;     // Security header type: integrity protected with new 5GS context
			tmp[off++] = mac[0];   // MAC-I (4 bytes)
			tmp[off++] = mac[1];
			tmp[off++] = mac[2];
			tmp[off++] = mac[3];
			tmp[off++] = seq;      // Sequence number = COUNT LSB
			memcpy(&tmp[off], nas_5g, out); // Copy inner plain NAS (starts with 0x7E 0x00 ...)
			off += out;

			// Copy back to output buffer
			memcpy(nas_5g, tmp, off);
			*nas_5g_len = off;

			LOG_INFO("Built 5G Security Protected NAS (SMC Complete) with integrity\n");

			/* COUNT++ AFTER MAC computation — ordering is security-critical */
			LOG_DEBUG("[COUNT-INC] Before increment: nas_ul_count_5g=0x%08X\n",
				   ((ue_id_mapping_t*)security_map)->nas_ul_count_5g);
			((ue_id_mapping_t*)security_map)->nas_ul_count_5g++;
			LOG_DEBUG("[COUNT-INC] After increment: nas_ul_count_5g=0x%08X\n",
				   ((ue_id_mapping_t*)security_map)->nas_ul_count_5g);
			((ue_id_mapping_t*)security_map)->has_sent_smc = true;

		} else {
			LOG_ERROR("Failed to compute 5G uplink MAC for integrity protection\n");
			return -1;
		}
	} else if (security_map && security_map->has_nas_keys) {
		// Fallback: Use 4G security context
		LOG_WARN("Using 4G security context (5G keys not available)\n");
		LOG_INFO("Sending plain 5G NAS to AMF (no 5G keys)\n");
		*nas_5g_len = out; // cannot integrity-protect without 5G NAS keys
	} else {
		// No security context available, send plain
		LOG_INFO("No security context available, sending plain Security Mode Complete\n");
		*nas_5g_len = out;
	}

	char detail[128];
	char imeisv_detail[32];
	if (imeisv_present) {
		snprintf(imeisv_detail, sizeof(imeisv_detail), "present(len=%u)", imeisv_len);
	} else {
		snprintf(imeisv_detail, sizeof(imeisv_detail), "absent");
	}
	snprintf(detail, sizeof(detail), "ngKSI=0x%02X, IMEISV=%s, addSec=%s",
		 ngksi_octet & 0x0F,
		 imeisv_detail,
		 additional_present ? "present" : "absent");
	s1n2_log_security_mode_result("uplink", true, first_byte & 0x0F, msg_type, detail);
	LOG_INFO("5G Security Mode Complete created (len=%zu, UEcap=%u)\n", out, ue_cap_len);

	// Derive KeNB from KASME (for Initial Context Setup Request)
	// MME derives KeNB after receiving Security Mode Complete (TS 33.401 A.3)
	if (security_map && security_map->has_kasme) {
		uint32_t ul_count = security_map->nas_ul_count; // Use current uplink NAS COUNT
		if (s1n2_kdf_kenb(security_map->kasme, ul_count, security_map->kenb) == 0) {
			security_map->has_kenb = true;
			security_map->kenb_ul_count = ul_count;

		} else {
			security_map->has_kenb = false;

		}
	} else {

	}

	return 0;
}
