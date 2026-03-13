/**
 * @file security/security_mac_and_algo.c
 * @brief Shared security helpers: 5G uplink MAC, algorithm mapping tables
 *
 * Extracted from nas_helpers.c during Phase 3 NAS modularization.
 *
 * Contains:
 *   - s1n2_compute_5g_uplink_mac() — MAC computation for 5G uplink NAS
 *   - s1n2_nea_to_eea_map[] / s1n2_nia_to_eia_map[] — algorithm mapping
 *
 * @see 3GPP TS 33.401 (EPS Security)
 * @see 3GPP TS 33.501 (5GS Security)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"

/* ================================================================
 * Algorithm mapping tables (NEA↔EEA, NIA↔EIA)
 * ================================================================ */

const uint8_t s1n2_nea_to_eea_map[8] = {
	0x00, // NEA0 -> EEA0
	0x01, // NEA1 -> 128-EEA1
	0x02, // NEA2 -> 128-EEA2
	0x03, // NEA3 -> 128-EEA3
	0x04, // Reserved -> map to EEA4 (not supported but keeps bit position)
	0x05,
	0x06,
	0x07
};

const uint8_t s1n2_nia_to_eia_map[8] = {
	0x00, // NIA0 -> EIA0 (not supported, but retain value for completeness)
	0x01, // NIA1 -> 128-EIA1
	0x02, // NIA2 -> 128-EIA2
	0x03, // NIA3 -> 128-EIA3
	0x04,
	0x05,
	0x06,
	0x07
};

/* ================================================================
 * 5G uplink NAS MAC computation
 * ================================================================ */

int s1n2_compute_5g_uplink_mac(
    const ue_id_mapping_t *ue_map,
    const uint8_t *plain_nas,
    size_t plain_len,
    uint8_t *mac_out
) {
	if (!ue_map || !plain_nas || !mac_out || plain_len == 0) {
		printf("[ERROR] Invalid parameters for 5G uplink MAC computation\n");
		return -1;
	}

	// Select appropriate key: 5G key if available, otherwise fall back to 4G key
	const uint8_t *key_to_use = NULL;
	const char *key_type = NULL;

	if (ue_map->has_5g_nas_keys) {
		key_to_use = ue_map->k_nas_int_5g;
		key_type = "K_NASint_5G (from Kamf)";
	} else if (ue_map->has_nas_keys) {
		key_to_use = ue_map->k_nas_int;
		key_type = "K_NASint_4G (from K_ASME)";
		printf("[WARN] Using 4G NAS key for 5G Security Mode Complete - may cause MAC mismatch!\n");
	} else {
		printf("[ERROR] No NAS keys available for MAC computation\n");
		return -1;
	}

	// 5G uplink NAS parameters
	// 3GPP TS 33.401/33.501: Direction bit is 0 for Uplink, 1 for Downlink
	uint8_t direction = 0;  // 0 = uplink (UE -> Network)
	// For NAS signalling over 3GPP access, Open5GS AMF uses BEARER=1 in EIA2 header
	// This must match AMF's expectation to pass MAC verification
	uint8_t bearer = 1;     // NAS signalling bearer (Open5GS uses 1)
	uint32_t count = ue_map->nas_ul_count_5g;

	// Use NIA2/EIA2 (AES-CMAC) - most common algorithm
	// TODO: Get actual algorithm from ue_map if available
	s1n2_nas_integrity_alg_t alg = S1N2_NAS_EIA2;

	printf("[DEBUG] [MAC-CALC] Computing 5G uplink MAC with %s\n", key_type);
	printf("[DEBUG] [MAC-CALC] COUNT=0x%08X, Direction=%u, Bearer=%u, Alg=EIA2\n", count, direction, bearer);
	printf("[DEBUG] [MAC-CALC] UE Context: RAN-UE=%ld, AMF-UE=%ld\n",
	       ue_map->ran_ue_ngap_id, ue_map->amf_ue_ngap_id);
	printf("[DEBUG] %s: ", key_type);
	for (int i = 0; i < 16; i++) {
		printf("%02X", key_to_use[i]);
	}
	printf("\n");
	printf("[DEBUG] [MAC-CALC] Plain NAS len=%zu, head: ", plain_len);
	for (size_t i = 0; i < plain_len && i < 16; ++i) printf("%02X", plain_nas[i]);
	if (plain_len > 16) printf("..");
	printf("\n");

	// For 5G NAS uplink, the MAC is computed over: [SEQ (1 byte)] || [plain NAS]
	// where SEQ is the LSB of COUNT.
	uint8_t seq = (uint8_t)(count & 0xFF);
	uint8_t mac_input_buf[1 + 1024];
	if (plain_len > 1024) {
		printf("[ERROR] Plain NAS too large for MAC input: %zu bytes\n", plain_len);
		return -1;
	}
	mac_input_buf[0] = seq;
	memcpy(&mac_input_buf[1], plain_nas, plain_len);

	// Extra visibility to diagnose mismatches with AMF
	printf("[DEBUG] [MAC-CALC] SEQ=0x%02X, MAC-INPUT(%zu bytes) head: ", seq, plain_len + 1);
	for (size_t i = 0; i < (plain_len + 1) && i < 24; ++i) {
		printf("%02X", mac_input_buf[i]);
	}
	if (plain_len + 1 > 24) printf("..");
	printf("\n");

	// Compute MAC using existing security function over [SEQ + plain NAS]
	int ret = s1n2_nas_compute_mac(alg, key_to_use, count,
								   bearer, direction, mac_input_buf, plain_len + 1, mac_out);

	if (ret == 0) {
		printf("[DEBUG] 5G uplink MAC computed: %02X %02X %02X %02X\n",
		       mac_out[0], mac_out[1], mac_out[2], mac_out[3]);
	} else {
		printf("[ERROR] Failed to compute 5G uplink MAC\n");
	}

	return ret;
}
