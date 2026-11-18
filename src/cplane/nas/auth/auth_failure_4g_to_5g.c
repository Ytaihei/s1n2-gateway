#include "s1n2_log.h"
/**
 * @file auth/auth_failure_4g_to_5g.c
 * @brief 4G Authentication Failure (0x5C) → 5G Authentication Failure (0x59)
 *
 * Parses EMM cause and AUTS (SQN resynchronization) from 4G Authentication
 * Failure, builds 5G Authentication Failure with AUTS IE.
 * Optionally decodes UE's expected SQN for diagnostics/MongoDB update hints.
 *
 * Extracted from nas_4g_to_5g.c during Phase 2 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "subscriber_auth.h"
#include "internal/nas_conversion_internal.h"
#include "auth/auth.h"

int auth_failure_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                  size_t payload_offset,
                                  uint8_t *nas_5g, size_t *nas_5g_len,
                                  s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
	if (!nas_4g || !nas_5g || !nas_5g_len || nas_4g_len == 0) {
		return -1;
	}

	LOG_INFO("Converting 4G Authentication Failure (0x5C) -> 5G Authentication Failure (0x59) with AUTS (if present)\n");

	// 4G Authentication Failure 構造 (TS 24.301):
	//   Octet 3: EMM cause (例: 21=Synch failure)
	//   Octet 4以降: 任意IE
	//     - Authentication Failure Parameter (IEI=0x30, len=14, AUTS)
	if (nas_4g_len < payload_offset + 1) {
		LOG_ERROR("4G Authentication Failure too short (len=%zu)\n", nas_4g_len);
		return -1;
	}

	uint8_t emm_cause = nas_4g[payload_offset];
	LOG_DEBUG("4G Auth Failure cause=%u, optional IE bytes=%zu\n",
	       emm_cause, nas_4g_len - (payload_offset + 1));
	size_t ie_off = payload_offset + 1;
	bool has_auts = false;
	uint8_t auts[14] = {0};

	// 単純なスキャンでIEI=0x30(AUTS)を探索
	while (ie_off + 1 < nas_4g_len) {
		uint8_t iei = nas_4g[ie_off++];
		if (iei == 0x30) {
			if (ie_off >= nas_4g_len) break;
			uint8_t len = nas_4g[ie_off++];
			if (len == 14 && ie_off + 14 <= nas_4g_len) {
				memcpy(auts, nas_4g + ie_off, 14);
				has_auts = true;
				LOG_INFO("Parsed AUTS from 4G Authentication Failure (len=14)\n");
			} else {
				LOG_WARN("Authentication Failure Parameter present but unexpected length=%u\n", len);
			}
			break;
		} else {
			// 未対応IEIはここではスキップ不可なので中断
			LOG_WARN("Unsupported IEI 0x%02X while parsing Auth Failure (offset=%zu), stopping parse\n",
			       iei, ie_off - 1);
			break;
		}
	}
	if (!has_auts) {
		LOG_WARN("No AUTS found in 4G Authentication Failure (cause=%u)\n", emm_cause);
	}

	// 5G Authentication Failure 構築 (TS 24.501):
	//   EPd=0x7E, SHT=0x00, MT=0x59
	//   5GMM cause (1 octet) を付与（4GのEMM causeを踏襲）
	//   Authentication failure parameter (IEI=0x30, len=14, AUTS) を付与（存在時）
	size_t nas_5g_offset = 0;
	size_t required_len = 3 + 1 + (has_auts ? (1 + 1 + 14) : 0);
	if (*nas_5g_len < required_len) {
		LOG_ERROR("Output buffer too small for 5G Authentication Failure (need=%zu have=%zu)\n",
		       required_len, *nas_5g_len);
		return -1;
	}
	nas_5g[nas_5g_offset++] = 0x7E; // EPd: 5GMM
	nas_5g[nas_5g_offset++] = 0x00; // Security header type: plain
	nas_5g[nas_5g_offset++] = 0x59; // Message type: Authentication failure
	nas_5g[nas_5g_offset++] = emm_cause; // 5GMM cause（値は4GのEMM causeを流用）

	if (has_auts) {
		nas_5g[nas_5g_offset++] = 0x30; // IEI: Authentication failure parameter
		nas_5g[nas_5g_offset++] = 14;   // Length
		memcpy(nas_5g + nas_5g_offset, auts, 14);
		nas_5g[nas_5g_offset] ^= 0x00; // no-op to keep style consistent
		nas_5g_offset += 14;
	}

	*nas_5g_len = nas_5g_offset;

	LOG_INFO("5G Authentication Failure created (len=%zu, cause=%u, auts=%s)\n",
		   *nas_5g_len, emm_cause, has_auts ? "present" : "absent");
	if (has_auts) {

		// Decode UE's expected SQN from AUTS
		// AUTS = SQN_MS ⊕ AK || MAC-S
		// We need: K, OPc, RAND (from UE context)
		if (ue_map && ue_map->rand_cached) {
			// Get auth context from converter context
			s1n2_auth_context_t *auth_ctx_tmp = NULL;
			if (ctx && ctx->auth_ctx) {
				auth_ctx_tmp = (s1n2_auth_context_t*)(ctx->auth_ctx);
			}
			if (!auth_ctx_tmp) {
				auth_ctx_tmp = s1n2_context_get_shared_auth();
			}
			if (auth_ctx_tmp) {
				s1n2_subscriber_keys_t *keys = s1n2_auth_get_keys(auth_ctx_tmp, ue_map->imsi);
				if (keys && keys->configured) {
					uint8_t sqn_ms[6];
					if (s1n2_decode_auts_sqn(keys->opc, keys->ki, ue_map->rand, auts, sqn_ms) == 0) {
						// Convert SQN to uint64_t for display
						uint64_t sqn_value = 0;
						for (int i = 0; i < 6; i++) {
							sqn_value = (sqn_value << 8) | sqn_ms[i];
						}

						LOG_INFO("========== AUTS ANALYSIS (Sync Failure) ==========\n");

						LOG_INFO("UE expected SQN (dec): %lu\n", sqn_value);

						LOG_INFO("To resolve Sync Failure, update MongoDB:\n");
						LOG_INFO("  docker exec -it mongo-s1n2 mongosh --quiet open5gs \\\n");

						LOG_INFO("    {$set: {\"security.sqn\": NumberLong(\"%lu\")}})'\n", sqn_value + 1000);
						LOG_INFO("====================================================\n");
					} else {
						LOG_WARN("Failed to decode AUTS SQN (missing auth context)\n");
					}
				} else {

				}
			}
		} else {
			LOG_WARN("Cannot decode AUTS: UE mapping or auth data not available\n");
		}
	}

	return 0;
}
