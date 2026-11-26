#include "s1n2_log.h"
/**
 * @file auth/auth_response_4g_to_5g.c
 * @brief 4G Authentication Response (0x53) → 5G Authentication Response (0x57)
 *
 * Parses 4G RES, computes 5G RES* using subscriber keys, and derives
 * both 4G and 5G NAS keys:
 *   4G: CK,IK → KASME → K_NAS_int/enc (for 4G Security Mode)
 *   5G: CK,IK → Kausf → Kseaf → Kamf → K_NAS_int/enc_5G (for 5G SMC MAC)
 *
 * ⚠️ SECURITY CRITICAL: Key derivation order must be preserved.
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
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "auth/auth.h"

int auth_response_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                   size_t payload_offset,
                                   uint8_t *nas_5g, size_t *nas_5g_len,
                                   s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
	if (!nas_4g || !nas_5g || !nas_5g_len || nas_4g_len == 0) {
		return -1;
	}

	uint8_t msg_type = 0x53;
	LOG_INFO("Converting 4G Authentication Response (0x%02X) -> 5G Authentication Response (0x57)\n", msg_type);

	if (nas_4g_len < payload_offset + 1) {
		LOG_ERROR("4G Authentication Response too short (len=%zu)\n", nas_4g_len);
		return -1;
	}

	size_t res_offset = payload_offset;
	uint8_t res_len = 0;
	const uint8_t *res_value = NULL;

	if (res_offset < nas_4g_len) {
		// Check for optional RES IEI (0x2D)
		if (nas_4g[res_offset] == 0x2D) {
			res_offset++;
			if (res_offset >= nas_4g_len) {
				LOG_ERROR("4G Authentication Response truncated at RES IEI\n");
				return -1;
			}
		}
		// Read RES length
		res_len = nas_4g[res_offset++];
		if (res_offset + res_len > nas_4g_len) {
			LOG_ERROR("4G Authentication Response RES length mismatch (len=%u, available=%zu)\n",
				   res_len, nas_4g_len - res_offset);
			return -1;
		}
		res_value = &nas_4g[res_offset];
	} else {
		LOG_ERROR("4G Authentication Response missing RES\n");
		return -1;
	}

	LOG_DEBUG("4G authentication response length=%u", res_len);

	size_t nas_5g_offset = 0;
	const uint8_t res_star_len = 16;
	size_t required_len = 3 + 1 + 1 + res_star_len;

	if (*nas_5g_len < required_len) {
		LOG_ERROR("Output buffer too small for 5G Authentication Response (need %zu, have %zu)\n",
			   required_len, *nas_5g_len);
		return -1;
	}

	nas_5g[nas_5g_offset++] = 0x7E;
	nas_5g[nas_5g_offset++] = 0x00;
	nas_5g[nas_5g_offset++] = 0x57;
	nas_5g[nas_5g_offset++] = 0x2D;
	nas_5g[nas_5g_offset++] = res_star_len;

	uint8_t res_star[16] = {0};
	bool res_star_computed = false;

	s1n2_auth_context_t *auth_ctx_ptr = NULL;
	if (ctx && ctx->auth_ctx) {
		auth_ctx_ptr = (s1n2_auth_context_t*)(ctx->auth_ctx);
	}
	if (!auth_ctx_ptr) {
		auth_ctx_ptr = s1n2_context_get_shared_auth();
	}

	if (auth_ctx_ptr) {
		ue_id_mapping_t *ue_mapping = NULL;
		// Strict: Use only the provided UE mapping when it already has cached RAND/AUTN/IMSI
		if (ue_map && ue_map->rand_cached && ue_map->autn_cached && ue_map->imsi[0] != '\0') {
			ue_mapping = ue_map;
			LOG_DEBUG("Using provided UE mapping (ENB=%ld,RAN=%ld,AMF=%ld) for RES* computation\n",
				   ue_map->enb_ue_s1ap_id, ue_map->ran_ue_ngap_id, ue_map->amf_ue_ngap_id);
		}

		if (ue_mapping && ue_mapping->rand_cached && ue_mapping->autn_cached && ue_mapping->imsi[0] != '\0') {

			LOG_INFO(" (len=%u)\n", res_len);

			if (s1n2_auth_compute_res_star_with_imsi(auth_ctx_ptr, ue_mapping->imsi,
													  ue_mapping->rand,
													  ue_mapping->sqn_xor_ak,
													  res_value, res_len, res_star) == 0) {
				LOG_INFO("RES* computed successfully using cryptographic functions\n");

				res_star_computed = true;

				// ===== KEY DERIVATION: 4G AND 5G NAS keys =====
				LOG_INFO("Deriving 4G and 5G NAS keys for Security Mode Command/Complete\n");

				// Get subscriber keys (Ki, OPc)
				s1n2_subscriber_keys_t *keys = s1n2_auth_get_keys(auth_ctx_ptr, ue_mapping->imsi);
				if (keys && keys->configured) {
					// Extract PLMN ID from IMSI (MCC+MNC)
					// TODO: Extract dynamically from Registration Request
					uint8_t plmn_id[3] = {0x00, 0xF1, 0x10}; // MCC=001, MNC=01

					// Compute CK and IK for both 4G and 5G key derivation
					uint8_t ck[16], ik[16];
					s1n2_milenage_f2345(keys->opc, keys->ki, ue_mapping->rand,
					                    NULL, ck, ik, NULL);

					// Derive 4G NAS keys (for 4G Security Mode Command to eNB)
					uint8_t int_alg = 2; // EIA2 (AES-CMAC)
					uint8_t enc_alg = 2; // EEA2 (AES-CTR)

					if (s1n2_derive_4g_nas_keys(keys->ki, keys->opc,
					                            ue_mapping->rand,
					                            ue_mapping->sqn_xor_ak,
					                            plmn_id,
					                            int_alg, enc_alg,
					                            ue_mapping->k_nas_int,
					                            ue_mapping->k_nas_enc) == 0) {
						ue_mapping->has_nas_keys = true;
						ue_mapping->nas_dl_count = 0;
						ue_mapping->nas_ul_count = 0;
						LOG_INFO("4G NAS keys derived for UE\n");

						// Derive KASME for ICS (KeNB will be derived later after Security Mode Complete)
						if (s1n2_kdf_kasme(ck, ik, ue_mapping->sqn_xor_ak, plmn_id, ue_mapping->kasme) == 0) {
							ue_mapping->has_kasme = true;

						} else {
							ue_mapping->has_kasme = false;

						}
					} else {
						LOG_WARN("Failed to derive 4G NAS keys\n");
						ue_mapping->has_nas_keys = false;
					}

					// Derive 5G NAS keys (for 5G Security Mode Complete MAC to AMF)
					// CK||IK -> Kausf -> Kseaf -> Kamf -> K_NASint_5g, K_NASenc_5g
					const char *serving_network = "5G:mnc001.mcc001.3gppnetwork.org";

					// Step 1: Derive Kausf
					if (s1n2_kdf_kausf(ck, ik, ue_mapping->sqn_xor_ak, serving_network, ue_mapping->kausf) == 0) {

						// Step 2: Derive Kseaf from Kausf
						if (s1n2_kdf_kseaf(ue_mapping->kausf, serving_network, ue_mapping->kseaf) == 0) {

							// Step 3: Derive Kamf from Kseaf
							// Build SUPI from IMSI
							char supi[32];
							snprintf(supi, sizeof(supi), "imsi-%s", ue_mapping->imsi);

							// Use cached ABBA (or default 0x0000 if not available)
							uint8_t abba[2] = {0x00, 0x00};
							uint8_t abba_len = 2;
							if (ue_mapping->abba_len == 2) {
								memcpy(abba, ue_mapping->abba, 2);

							} else {

							}

							if (s1n2_kdf_kamf(ue_mapping->kseaf, supi, abba, abba_len, ue_mapping->kamf) == 0) {

								// Step 4: Derive 5G NAS keys from Kamf
								// NOTE: To interoperate with our AMF (Open5GS), we use type=0x02 for integrity and 0x01 for encryption.
								// TS 33.501 A.8 defines P0 type distinguisher (0x01=NIA, 0x02=NEA) but AMF derives K_NASint from type=0x02.
								// Algorithm ID: 2 for 128-5G-IA2/NIA2
								if (s1n2_kdf_nas_5g(ue_mapping->kamf, 0x02 /* integrity */ , int_alg, ue_mapping->k_nas_int_5g) == 0 &&
									s1n2_kdf_nas_5g(ue_mapping->kamf, 0x01 /* encryption */, enc_alg, ue_mapping->k_nas_enc_5g) == 0) {
									ue_mapping->has_5g_nas_keys = true;
									ue_mapping->nas_ul_count_5g = 0;
									LOG_INFO("5G NAS keys derived for Security Mode Complete MAC\n");

								} else {
									LOG_WARN("Failed to derive 5G NAS keys\n");
								}
							} else {

							}
						} else {

						}
					} else {

					}
				} else {

					ue_mapping->has_nas_keys = false;
				}
				// ===== END KEY DERIVATION =====
				ue_mapping->rand_cached = false;
				memset(ue_mapping->rand, 0, sizeof(ue_mapping->rand));
				ue_mapping->autn_cached = false;
				memset(ue_mapping->autn, 0, sizeof(ue_mapping->autn));
				memset(ue_mapping->sqn_xor_ak, 0, sizeof(ue_mapping->sqn_xor_ak));
			} else {
				LOG_ERROR("Failed to compute RES* - falling back to zero-padding\n");
			}
		} else {
			// Do NOT search other UE mappings; avoid cross-UE RAND mix-ups.
			if (!ue_map) {
				LOG_ERROR("No UE mapping provided to RES* computation path; aborting conversion.\n");
			} else {

			}
			LOG_INFO("[HINT] Ensure RAND/AUTN/ABBA are cached from 5G Authentication Request before sending Authentication Response.\n");
		}
	} else {
		LOG_ERROR("Authentication context unavailable; aborting conversion.\n");
	}

	if (!res_star_computed) {
		LOG_ERROR("Could not compute 5G RES*; conversion of Authentication Response aborted.\n");
		return -1;
	}

	memcpy(nas_5g + nas_5g_offset, res_star, res_star_len);
	nas_5g_offset += res_star_len;

	*nas_5g_len = nas_5g_offset;

	LOG_INFO("5G Authentication Response created (len=%zu, RES*_len=16, original_RES_len=%u)\n",
		   *nas_5g_len, res_len);

	return 0;
}
