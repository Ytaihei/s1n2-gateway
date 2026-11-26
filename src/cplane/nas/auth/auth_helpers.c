#include "s1n2_log.h"
/**
 * @file auth/auth_helpers.c
 * @brief Helper functions for Authentication module
 *
 * Contains RAND/AUTN extraction from 5G Authentication Request.
 *
 * Extracted from nas_4g_to_5g_helpers.c during Phase 2 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"

/* ================================================================
 * Auth extraction from 5G NAS
 * ================================================================ */

int s1n2_extract_rand_autn_from_5g_auth_request(const uint8_t *nas_pdu, size_t nas_len,
						 uint8_t *rand_out,
						 uint8_t *autn_out,
						 uint8_t *sqn_xor_ak_out,
						 ue_id_mapping_t *ue_map) {
	if (!nas_pdu || nas_len < 3 || !rand_out) {
		return -1;
	}

	size_t offset = 0;

	if (nas_pdu[offset] != 0x7E) {
		LOG_WARN("Not a 5G NAS message (EPD=0x%02X)\n", nas_pdu[offset]);
		return -1;
	}
	offset++;

	offset++;

	if (nas_pdu[offset] != 0x56) {
		LOG_DEBUG("Not an Authentication Request (type=0x%02X)\n", nas_pdu[offset]);
		return -1;
	}
	offset++;

	LOG_INFO("5G Authentication Request detected, extracting RAND...\n");

	if (offset >= nas_len) return -1;
	offset++;  // Skip ngKSI

	if (offset >= nas_len) return -1;
	uint8_t abba_len = nas_pdu[offset];
	offset++;

	// Cache ABBA for 5G key derivation
	if (ue_map && abba_len >= 2 && offset + abba_len <= nas_len) {
		memcpy(ue_map->abba, &nas_pdu[offset], 2);
		ue_map->abba_len = 2;
		LOG_INFO("Cached ABBA (from 5G AuthReq): %02X %02X (len=%u)\n",
			   ue_map->abba[0], ue_map->abba[1], (unsigned)ue_map->abba_len);
	} else {
		LOG_DEBUG("ABBA not cached from AuthReq (abba_len=%u, remain=%zu, have_ue_map=%d)\n",
			   (unsigned)abba_len,
			   (offset + abba_len <= nas_len) ? (nas_len - (offset + abba_len)) : 0,
			   ue_map ? 1 : 0);
	}
	offset += abba_len;

	bool rand_found = false;
	bool autn_found = false;

	while (offset < nas_len) {
		uint8_t iei = nas_pdu[offset++];

		if (iei == 0x21) {
			if (offset + 16 > nas_len) {
				LOG_ERROR("RAND truncated\n");
				return -1;
			}
			if (rand_out) {
				memcpy(rand_out, &nas_pdu[offset], 16);
			}
			offset += 16;
			rand_found = true;

		} else if (iei == 0x20) {
			if (offset >= nas_len) {
				LOG_ERROR("AUTN length missing\n");
				return -1;
			}
			uint8_t autn_len = nas_pdu[offset++];
			if (offset + autn_len > nas_len) {
				LOG_ERROR("AUTN truncated (len=%u, remaining=%zu)\n", autn_len, nas_len - offset);
				return -1;
			}
			if (autn_out && autn_len >= 16) {
				memcpy(autn_out, &nas_pdu[offset], 16);
			}
			if (sqn_xor_ak_out && autn_len >= 6) {
				memcpy(sqn_xor_ak_out, &nas_pdu[offset], 6);
			}
			offset += autn_len;
			autn_found = true;
		} else {
			if (offset >= nas_len) {
				break;
			}
			uint8_t len = nas_pdu[offset++];
			if (offset + len > nas_len) {
				LOG_WARN("Skipping truncated IEI=0x%02X\n", iei);
				return -1;
			}
			offset += len;
		}

		if (rand_found && autn_found) {
			return 0;
		}
	}

	LOG_WARN("Failed to extract complete RAND/AUTN from Authentication Request\n");
	return -1;
}
