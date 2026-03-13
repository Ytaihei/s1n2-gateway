/**
 * @file registration/registration_accept_5g_to_4g.c
 * @brief 5G Registration Accept (0x42) → 4G Attach Accept (0x42)
 *
 * Phase 5 of NAS modularization.
 * Extracted from nas_5g_to_4g.c (case 0x42).
 *
 * Builds complete 4G Attach Accept with:
 *   - EPS attach result, T3412, TAI list
 *   - ESM container (cached PDN connectivity request + Activate default bearer)
 *   - NAS security wrapping (cipher+integrity or integrity-only)
 *
 * Caches 5G-GUTI and registration accept artifacts in ue_map.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "internal/nas_module_common.h"
#include "registration/registration.h"

int registration_accept_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                         uint8_t *nas_4g, size_t *nas_4g_len,
                                         ue_id_mapping_t *security_cache) {
	// We likely cannot decrypt 5G NAS here (downlink usually ciphered). Synthesize minimal 4G Accept.
	printf("[INFO] Converting 5G Registration Accept (0x42) -> 4G Attach Accept (0x42) [minimal]\n");
	if (security_cache) {
		s1n2_cache_registration_accept_artifacts(security_cache, msg, msg_len);
		s1n2_context_mark_tau_complete(security_cache);
	}

	// Build minimal 4G Attach Accept:
	// Octet1: 0x07 (EPS Mobility Management, plain)
	// Octet2: 0x42 (Attach accept)
	// Octet3: EPS attach result (1=EPS only)
	// IE: T3412 value (IEI=0x5C, len=1) - choose a sane default (e.g., 54 minutes: unit=6 min, value=9 -> 0x19)
	// IE: TAI list (IEI=0x54, len=6): one TAI (PLMN from env, TAC from env)

	size_t cap = *nas_4g_len; // available capacity provided by caller
	uint8_t out[256];
	size_t out_off = 0;
	// IEオフセット追跡用
	size_t off_attach_result = 0;
	size_t off_t3412 = 0;
	size_t off_tai = 0;
	size_t off_esm = 0;
	size_t out_capacity = (cap < sizeof(out)) ? cap : sizeof(out);
	if (out_capacity < 32) {
		printf("[WARN] Output buffer capacity seems too small (%zu bytes)\n", out_capacity);
	}

	out[out_off++] = 0x07; // EPS MM PD, plain
	out[out_off++] = 0x42; // Attach accept

	// EPS attach result
	off_attach_result = out_off;
	out[out_off++] = 0x01; // EPS attach result: EPS only (1)

	// Prepare PLMN and TAC (used by TAI list)
	char mcc[4] = {0};
	char mnc[4] = {0};
	int mnc_len = 3;
	s1n2_get_mcc_mnc_from_env(mcc, mnc, &mnc_len);
	uint8_t plmn[3];
	s1n2_encode_plmn_tbcd(mcc, mnc, mnc_len, plmn);
	uint16_t tac = s1n2_get_tac_from_env();

	// T3412 value (GPRS timer) - TS 24.301 Attach Accept: OPTIONAL, often omitted in successful traces
	// Add T3412 to match successful 4G pcap: value=0x29 (unit=1min, value=9 -> 9 minutes)
	// Format: V (value-only, no IEI) - single byte GPRS timer value
	off_t3412 = out_off; // mark position (but we're not adding it)
	out[out_off++] = 0x29; // GPRS Timer value: unit=001(1min), value=01001(9) = 9 minutes
	printf("[TRACE] AA T3412: value=0x29 (9 minutes, V format)\n");

	// TAI list - TS 24.301 Attach Accept: MANDATORY IE, format LV (no IEI, just length+value)
	// Successful trace shows: len(1 byte) + value(6 bytes) = 06 40 00 f1 10 00 01
	off_tai = out_off;
	out[out_off++] = 0x06; // length of TAI list value (type+num + one TAI)
	// Use Type=2 (explicit one-PLMN, consecutive TACs) to align with known-good 4G pcap behavior
	// and further reduce Wireshark's occasional list-count hinting.
	out[out_off++] = 0x40; // type=2 (consecutive), num=0 (one element)
	// PLMN (3 bytes TBCD)
	out[out_off++] = plmn[0];
	out[out_off++] = plmn[1];
	out[out_off++] = plmn[2];
	// TAC (2 bytes big-endian)
	out[out_off++] = (uint8_t)((tac >> 8) & 0xFF);
	out[out_off++] = (uint8_t)(tac & 0xFF);
	printf("[TRACE] AA TAI at off=%zu (LV, no IEI): len=%u, type/num=%02X, PLMN=%02X%02X%02X, TAC=%02X%02X\n",
	       off_tai, 6U,
	       out[off_tai+1], out[off_tai+2], out[off_tai+3], out[off_tai+4],
	       out[off_tai+5], out[off_tai+6]);
	if (out_off > out_capacity) {
		printf("[ERROR] Output staging buffer overflow for Attach Accept (need %zu, cap %zu)\n", out_off, out_capacity);
		return -1;
	}

	printf("[INFO] Built base 4G Attach Accept (len=%zu, MCC=%c%c%c, MNC=%s, TAC=0x%04X)\n",
	   out_off, mcc[0], mcc[1], mcc[2], mnc, tac);
	printf("[DEBUG] 4G Attach Accept (pre-ESM) bytes: ");
	for (size_t i = 0; i < out_off && i < 64; ++i) printf("%02X ", out[i]);
	if (out_off > 64) printf("...");
	printf("\n");
	fflush(stdout);

	// Add ESM message container (IEI=0x78) with minimal Activate default EPS bearer context request (0xC1)
	// Build minimal ESM Activate Default EPS Bearer Context Request
	// ESM header: PD=ESM(0x2) + SecHdr=0 (0x02), MsgType=0xC1
	// Mandatory IEs for minimal interop: EPS Bearer ID(EBI=5), EPS QoS (defaults), APN, PDN Address (0.0.0.0)
	uint8_t esm[128];
	size_t esm_len = 0;

	// Successful MME behavior: Include UE's PDN connectivity request FIRST, then Activate default bearer
	// ESM1: UE's PDN connectivity request (from cached Attach Request)
	// ESM2: MME's Activate default EPS bearer context request

	if (security_cache && security_cache->has_cached_esm_pdn_request) {
		// Prepend cached PDN connectivity request (ESM1)
		if (esm_len + security_cache->cached_esm_pdn_request_len <= sizeof(esm)) {
			memcpy(esm + esm_len, security_cache->cached_esm_pdn_request, security_cache->cached_esm_pdn_request_len);
			esm_len += security_cache->cached_esm_pdn_request_len;
			printf("[INFO] Prepended cached ESM PDN connectivity request (len=%u)\n",
			       security_cache->cached_esm_pdn_request_len);
			const uint8_t *pco_ptr = NULL;
			uint8_t pco_len = 0;
			for (size_t scan = 0; scan + 1 < security_cache->cached_esm_pdn_request_len; ++scan) {
				if (security_cache->cached_esm_pdn_request[scan] == 0x27) {
					uint8_t len = security_cache->cached_esm_pdn_request[scan + 1];
					if (scan + 2 + len <= security_cache->cached_esm_pdn_request_len) {
						pco_ptr = &security_cache->cached_esm_pdn_request[scan + 2];
						pco_len = len;
					}
					break;
				}
			}
			if (pco_ptr && pco_len > 0) {
				s1n2_log_pco_entries("[DL NAS] Replayed PDN request PCO", pco_ptr, pco_len);
			}
		}
	}

	// ESM2: MME's Activate default EPS bearer context request
	// ESM first octet: EPS bearer identity (upper 4 bits) | PD=ESM(0x2)
	// 3GPP TS 24.301: Activate default EPS bearer context request では
	// ネットワークが割り当てるデフォルトEPSベアラの EBI を上位4bitに設定する慣行（多くのMMEは EBI=5）。
	// ICSで使用したE-RAB IDと一致させるのが自然。
	uint8_t ebi = 5; // default
	if (security_cache && security_cache->ics_e_rab_id >= 1 && security_cache->ics_e_rab_id <= 15) {
		ebi = security_cache->ics_e_rab_id;
	}
	esm[esm_len++] = (uint8_t)((ebi << 4) | 0x02);
	// Procedure Transaction Identity (match initial PDN connectivity PTI if既知; 既定で 0x01)
	esm[esm_len++] = 0x01; // PTI=1
	// Message type
	esm[esm_len++] = 0xC1; // Activate default EPS bearer context request
	// EPS QoS - MANDATORY IE in Activate default EPS bearer context request, format LV (no IEI)
	// Successful trace: 01 09 (len=1, QCI=9)
	esm[esm_len++] = 0x01; // len
	esm[esm_len++] = 0x09; // QCI=9 (best effort)
	// APN - MANDATORY IE, format LV (no IEI)
	// Successful trace: 09 08 "internet" (len=9, label encoding)
	char apn_str[64];
	size_t apn_strlen = s1n2_get_apn_from_env(apn_str, sizeof(apn_str));
	uint8_t apn_enc[64];
	size_t apn_enc_len = s1n2_encode_apn_label(apn_str, apn_enc, sizeof(apn_enc));
	if (apn_enc_len > 0) {
		if (esm_len + 1 + apn_enc_len <= sizeof(esm)) {
			esm[esm_len++] = (uint8_t)apn_enc_len;
			memcpy(esm + esm_len, apn_enc, apn_enc_len);
			esm_len += apn_enc_len;
		}
	}
	// PDN address - MANDATORY IE, format LV (no IEI)
	// Successful trace: 05 01 c0 a8 64 02 (len=5, type=IPv4, address)
	esm[esm_len++] = 0x05; // len = 1 (PDN type octet) + 4 (IPv4)
	esm[esm_len++] = 0x01; // PDN type = IPv4
	// Example: 192.168.100.2
	esm[esm_len++] = 0xC0; esm[esm_len++] = 0xA8; esm[esm_len++] = 0x64; esm[esm_len++] = 0x02;

	// PCO (Protocol Configuration Options) - OPTIONAL IE, IEI=0x27
	// Successful trace includes: 27 06 80 00 10 02 01 00 -> modified to: 5e 06 fe fe fa fa 02 02
	// For maximum compatibility, include minimal PCO matching successful trace pattern
	if (esm_len + 8 <= sizeof(esm)) {
		esm[esm_len++] = 0x5E; // PCO IEI (note: successful trace shows 0x5E, not 0x27)
		esm[esm_len++] = 0x06; // length = 6 bytes
		esm[esm_len++] = 0xFE; // Configuration protocol (0xFE = reserved/vendor specific)
		esm[esm_len++] = 0xFE;
		esm[esm_len++] = 0xFA;
		esm[esm_len++] = 0xFA;
		esm[esm_len++] = 0x02;
		esm[esm_len++] = 0x02;
		printf("[INFO] Added PCO (8 bytes: 5e 06 fe fe fa fa 02 02) matching successful trace\n");
	}

	// Now wrap in ESM message container in Attach Accept
	// Format: 2-byte length (big-endian) + value
	// Successful trace: 00 1d ... (len=0x001d=29 bytes, 2-byte big-endian)
	if (out_off + 2 + esm_len <= out_capacity) {
		uint16_t esm_len_be = htons((uint16_t)esm_len);
		memcpy(out + out_off, &esm_len_be, 2); // ESM container length (2 bytes, big-endian)
		out_off += 2;
		memcpy(out + out_off, esm, esm_len);
		off_esm = out_off; // 記録: ESM中身の開始位置
		out_off += esm_len;
		printf("[INFO] Appended ESM container (2-byte length) with Activate default EPS bearer request (len=%zu, APN=%s)\n", esm_len, apn_str);
		// 詳細トレース: ESM container先頭部
		{
			printf("[TRACE] ESM payload at off=%zu: ", off_esm);
			for (size_t i = 0; i < esm_len && i < 24; ++i) printf("%02X ", out[off_esm + i]);
			printf("\n");
		}
	} else {
		printf("[WARN] Not enough space to append ESM container to Attach Accept (need tail=%zu, cap=%zu)\n",
			(2UL + esm_len), out_capacity - out_off);
	}

	// Finalize: copy to caller buffer
	if (out_off > cap) {
		printf("[ERROR] Caller buffer too small for final Attach Accept (need %zu, have %zu)\n", out_off, cap);
		return -1;
	}
	// If we have 4G NAS keys and security context, wrap Attach Accept with NAS security
	// Prefer ciphering+integrity (0x27) if encryption key is available; otherwise integrity-only (0x17)
	bool wrapped = false;
	if (security_cache && security_cache->has_nas_keys) {
		// Determine integrity alg from cached selection if available; default to EIA2
		// TS 24.301 Section 9.9.3.23: NAS security algorithms
		// Bits 7,3: Spare (0), Bits 6-4: EEA, Bits 2-0: EIA
		uint8_t eia_sel = security_cache->selected_nas_security_alg & 0x07;          // Bits 2-0
		uint8_t eea_sel = (security_cache->selected_nas_security_alg >> 4) & 0x07;   // Bits 6-4

		printf("[DEBUG] [ATTACH-ACCEPT] Security algorithm selection: selected_nas_security_alg=0x%02X, EEA=%u, EIA=%u\n",
		       security_cache->selected_nas_security_alg, eea_sel, eia_sel);

		s1n2_nas_integrity_alg_t alg = S1N2_NAS_EIA2;
		switch (eia_sel) {
			case 1: alg = S1N2_NAS_EIA1; break;
			case 2: alg = S1N2_NAS_EIA2; break;
			case 3: alg = S1N2_NAS_EIA3; break;
			default: alg = S1N2_NAS_EIA2; break;
		}

		uint32_t count_dl = security_cache->nas_dl_count;
		uint8_t seq = (uint8_t)(count_dl & 0xFF);
		uint8_t mac_input[1 + 384];
		if (out_off > 384) {
			printf("[WARN] Attach Accept too large (%zu) for MAC input staging, sending plain\n", out_off);
		} else {
			// Attempt encryption only if negotiated EEA != 0 (EEA0 = no ciphering)
			//  - eea_sel == 0: encryption disabled by SMC -> integrity-only (0x17)
			//  - eea_sel == 2: use EEA2 (AES-CTR)
			//  - others (1/3/...): not implemented -> fallback to integrity-only
			s1n2_nas_encryption_alg_t enc_alg = S1N2_NAS_EEA0;
			if (eea_sel == 2) {
				enc_alg = S1N2_NAS_EEA2;
			}
			uint8_t cipher[384];
			bool enc_ok = false;
			if (enc_alg != S1N2_NAS_EEA0) {
				if (s1n2_nas_encrypt(enc_alg, security_cache->k_nas_enc, count_dl, 0 /*bearer*/, 1 /*DL*/, out, out_off, cipher) == 0) {
					enc_ok = true;
				} else {
					printf("[WARN] NAS EEA%u encryption failed, will fallback to integrity-only\n", eea_sel);
				}
			} // if EEA0 negotiated, leave enc_ok=false to select integrity-only path

			uint8_t mac[4] = {0};
			mac_input[0] = seq;
			if (enc_ok) {
				memcpy(mac_input + 1, cipher, out_off);
				if (s1n2_compute_smc_mac(alg, security_cache->k_nas_int, count_dl, mac_input, 1 + out_off, mac) == 0) {
					size_t needed = 1 /*sec hdr*/ + 4 /*MAC*/ + 1 /*SEQ*/ + out_off;
					if (needed <= cap) {
						size_t w = 0;
						nas_4g[w++] = 0x27; // Ciphered + Integrity protected + EPS MM PD
						memcpy(nas_4g + w, mac, 4); w += 4;
						nas_4g[w++] = seq;
						memcpy(nas_4g + w, cipher, out_off); w += out_off;
						*nas_4g_len = w;
						wrapped = true;
						printf("[INFO] Wrapped Attach Accept with NAS cipher+integrity (EEA=%u,EIA=%u, COUNT-DL=0x%08X, SEQ=%u)\n",
						   eea_sel, eia_sel, count_dl, seq);
						printf("[DEBUG] MAC=%02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);
						uint32_t before = security_cache->nas_dl_count;
						security_cache->nas_dl_count = (security_cache->nas_dl_count + 1) & 0xFFFFFFFFu;
						printf("[DEBUG] [COUNT] DL NAS COUNT++ after Attach Accept: 0x%08X -> 0x%08X\n", before, security_cache->nas_dl_count);
						printf("[TRACE] AA IE map (protected+ciph): attach_result@%zu=%02X, t3412@%zu, tai@%zu, esm@%zu len~%zu\n",
						       off_attach_result, out[off_attach_result], off_t3412, off_tai, off_esm, (size_t)0);
					} else {
						printf("[WARN] Output buffer too small to wrap cipher+integrity (need %zu, have %zu)\n", needed, cap);
					}
				} else {
					printf("[WARN] Failed to compute NAS MAC over ciphered payload, falling back to integrity-only\n");
				}
			}

			if (!wrapped) {
				// Integrity-only fallback (0x17)
				memcpy(mac_input + 1, out, out_off);
				if (s1n2_compute_smc_mac(alg, security_cache->k_nas_int, count_dl, mac_input, 1 + out_off, mac) == 0) {
					size_t needed = 1 + 4 + 1 + out_off;
					if (needed <= cap) {
						size_t w = 0;
						nas_4g[w++] = 0x17; // Integrity protected + EPS MM PD
						memcpy(nas_4g + w, mac, 4); w += 4;
						nas_4g[w++] = seq;
						memcpy(nas_4g + w, out, out_off); w += out_off;
						*nas_4g_len = w;
						wrapped = true;
						printf("[INFO] Wrapped Attach Accept with NAS integrity (fallback or EEA0-negotiated) (EEA=%u,EIA=%u, COUNT-DL=0x%08X, SEQ=%u)\n",
						   eea_sel, eia_sel, count_dl, seq);
						printf("[DEBUG] MAC=%02X %02X %02X %02X\n", mac[0], mac[1], mac[2], mac[3]);
						uint32_t before = security_cache->nas_dl_count;
						security_cache->nas_dl_count = (security_cache->nas_dl_count + 1) & 0xFFFFFFFFu;
						printf("[DEBUG] [COUNT] DL NAS COUNT++ after Attach Accept: 0x%08X -> 0x%08X\n", before, security_cache->nas_dl_count);
						printf("[TRACE] AA IE map (protected): attach_result@%zu=%02X, t3412@%zu, tai@%zu, esm@%zu len~%zu\n",
						       off_attach_result, out[off_attach_result], off_t3412, off_tai, off_esm, (size_t)0);
					} else {
						printf("[WARN] Output buffer too small to wrap integrity (need %zu, have %zu)\n", needed, cap);
					}
				} else {
					printf("[WARN] Failed to compute NAS MAC for Attach Accept (fallback), sending plain\n");
				}
			}
		}
	}

	if (!wrapped) {
		memcpy(nas_4g, out, out_off);
		*nas_4g_len = out_off;
		printf("[INFO] Built 4G Attach Accept (final len=%zu) [plain]\n", out_off);
		printf("[TRACE] AA IE map (plain): attach_result@%zu=%02X, t3412@%zu, tai@%zu, esm@%zu len~%zu\n",
		       off_attach_result, out[off_attach_result], off_t3412, off_tai, off_esm, (size_t)0);
	} else {
		printf("[DEBUG] 4G Attach Accept (integrity-wrapped) bytes head: ");
		for (size_t i = 0; i < *nas_4g_len && i < 96; ++i) printf("%02X ", nas_4g[i]);
		if (*nas_4g_len > 96) printf("...");
		printf("\n");
	}
	fflush(stdout);

	(void)apn_strlen; /* suppress unused-variable warning */

	return 0;
}
