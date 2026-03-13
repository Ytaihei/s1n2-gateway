/**
 * @file shared/nas_plmn.c
 * @brief PLMN/TAC/SUCI helpers for NAS conversion modules
 *
 * Contains functions for environment-based PLMN/TAC/SUCI configuration,
 * digit parsing, and PLMN TBCD encoding.
 *
 * Extracted from nas_helpers.c during Phase 1 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suci_utils.h"

/* ================================================================
 * PLMN / TAC / SUCI environment helpers
 * ================================================================ */

void s1n2_copy_digits(const char *src, char *dst, size_t dst_len) {
	if (!dst || dst_len == 0) {
		return;
	}
	size_t written = 0;
	if (src) {
		for (size_t i = 0; src[i] != '\0' && written + 1 < dst_len; ++i) {
			if (src[i] >= '0' && src[i] <= '9') {
				dst[written++] = src[i];
			}
		}
	}
	dst[written] = '\0';
}

void s1n2_init_suci_config(suci_builder_config_t *cfg) {
	if (!cfg) {
		return;
	}
	memset(cfg, 0, sizeof(*cfg));

	const char *mcc = getenv("S1N2_MCC");
	if (!mcc || !*mcc) mcc = getenv("MCC");
	if (!mcc || !*mcc) mcc = "001";
	char mcc_digits[8] = {0};
	s1n2_copy_digits(mcc, mcc_digits, sizeof(mcc_digits));
	size_t mcc_digits_len = strlen(mcc_digits);
	if (mcc_digits_len < 3) {
		size_t pad = 3 - mcc_digits_len;
		for (size_t i = 0; i < pad; ++i) cfg->mcc[i] = '0';
		memcpy(cfg->mcc + pad, mcc_digits, mcc_digits_len);
	} else {
		memcpy(cfg->mcc, mcc_digits + (mcc_digits_len - 3), 3);
	}
	cfg->mcc[3] = '\0';

	const char *mnc = getenv("S1N2_MNC");
	if (!mnc || !*mnc) mnc = getenv("MNC");
	if (!mnc || !*mnc) mnc = "01";
	char mnc_digits[8] = {0};
	s1n2_copy_digits(mnc, mnc_digits, sizeof(mnc_digits));
	size_t mnc_digits_len = strlen(mnc_digits);
	if (mnc_digits_len == 0) {
		strcpy(cfg->mnc, "01");
		cfg->mnc_len = 2;
	} else {
		if (mnc_digits_len > 3) mnc_digits_len = 3;
		memcpy(cfg->mnc, mnc_digits, mnc_digits_len);
		cfg->mnc[mnc_digits_len] = '\0';
		cfg->mnc_len = (int)mnc_digits_len;
	}
	if (cfg->mnc_len != 2 && cfg->mnc_len != 3) {
		cfg->mnc_len = 3;
	}

	const char *routing = getenv("S1N2_SUCI_ROUTING_INDICATOR");
	if (!routing || !*routing) routing = getenv("S1N2_ROUTING_INDICATOR");
	if (routing && *routing) {
		s1n2_copy_digits(routing, cfg->routing_indicator, sizeof(cfg->routing_indicator));
	} else {
		cfg->routing_indicator[0] = '\0';
	}

	const char *scheme = getenv("S1N2_SUCI_PROTECTION_SCHEME");
	if (!scheme || !*scheme) scheme = "0";
	cfg->protection_scheme_id = (uint8_t)strtoul(scheme, NULL, 10) & 0x0F;

	const char *hnpki = getenv("S1N2_SUCI_HOME_PKI");
	if (!hnpki || !*hnpki) hnpki = "0";
	cfg->home_network_pki_value = (uint8_t)strtoul(hnpki, NULL, 10);
}

// Helper: get MCC/MNC from environment (reusing SUCI config logic)
void s1n2_get_mcc_mnc_from_env(char out_mcc[4], char out_mnc[4], int *out_mnc_len) {
	suci_builder_config_t cfg;
	s1n2_init_suci_config(&cfg);
	// cfg.mcc is 3 chars, cfg.mnc_len is 2 or 3, cfg.mnc is string
	memcpy(out_mcc, cfg.mcc, 3);
	out_mcc[3] = '\0';
	int mnc_len = (cfg.mnc_len == 2 || cfg.mnc_len == 3) ? cfg.mnc_len : 3;
	memcpy(out_mnc, cfg.mnc, mnc_len);
	out_mnc[mnc_len] = '\0';
	if (out_mnc_len) *out_mnc_len = mnc_len;
}

// Helper: encode PLMN in 3GPP TBCD (3 bytes) from MCC/MNC digits (chars '0'-'9').
void s1n2_encode_plmn_tbcd(const char mcc[4], const char mnc[4], int mnc_len, uint8_t plmn_out[3]) {
	// Octet1: MCC digit2 | MCC digit1
	uint8_t mcc1 = (uint8_t)(mcc[0] - '0') & 0x0F;
	uint8_t mcc2 = (uint8_t)(mcc[1] - '0') & 0x0F;
	uint8_t mcc3 = (uint8_t)(mcc[2] - '0') & 0x0F;
	uint8_t mnc1 = (uint8_t)(mnc[0] - '0') & 0x0F;
	uint8_t mnc2 = (uint8_t)(mnc[1] - '0') & 0x0F;
	uint8_t mnc3 = 0x0F; // 2-digit MNC default
	if (mnc_len == 3) {
		mnc3 = (uint8_t)(mnc[2] - '0') & 0x0F;
	}
	plmn_out[0] = (uint8_t)((mcc2 << 4) | mcc1);
	plmn_out[1] = (uint8_t)((mnc3 << 4) | mcc3);
	plmn_out[2] = (uint8_t)((mnc2 << 4) | mnc1);
}

// Helper: get TAC from environment (defaults to 0x0001)
uint16_t s1n2_get_tac_from_env(void) {
	const char *tac_env = getenv("S1N2_TAC");
	if (!tac_env || !*tac_env) tac_env = getenv("TAC");
	if (tac_env && *tac_env) {
		unsigned long tac_val = strtoul(tac_env, NULL, 0);
		if (tac_val <= 0xFFFFUL) return (uint16_t)tac_val;
	}
	return (uint16_t)0x0001;
}
