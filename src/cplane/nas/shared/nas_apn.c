/**
 * @file shared/nas_apn.c
 * @brief APN utility helpers for NAS conversion modules
 *
 * Contains functions for APN string handling and encoding,
 * including environment variable retrieval and 3GPP label encoding.
 *
 * Extracted from nas_5g_to_4g_helpers.c during Phase 1 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ================================================================
 * APN / string utility helpers
 * ================================================================ */

size_t s1n2_safe_strnlen(const char *text, size_t max_len) {
	if (!text) return 0;
	size_t len = 0;
	while (len < max_len && text[len] != '\0') {
		len++;
	}
	return len;
}

size_t s1n2_get_apn_from_env(char *apn_buf, size_t apn_buf_len) {
	if (!apn_buf || apn_buf_len == 0) return 0;
	const char *apn = getenv("S1N2_APN");
	if (!apn || !*apn) apn = getenv("APN");
	if (!apn || !*apn) apn = "internet";
	size_t n = s1n2_safe_strnlen(apn, apn_buf_len - 1);
	memcpy(apn_buf, apn, n);
	apn_buf[n] = '\0';
	return n;
}

size_t s1n2_encode_apn_label(const char *apn_str, uint8_t *out, size_t out_cap) {
	if (!apn_str || !out) return 0;
	size_t out_len = 0;
	const char *p = apn_str;
	while (*p) {
		// find next dot
		const char *dot = strchr(p, '.');
		size_t lab_len = dot ? (size_t)(dot - p) : strlen(p);
		if (lab_len == 0 || lab_len > 63) return 0; // invalid label
		if (out_len + 1 + lab_len > out_cap) return 0;
		out[out_len++] = (uint8_t)lab_len;
		memcpy(out + out_len, p, lab_len);
		out_len += lab_len;
		if (!dot) break;
		p = dot + 1;
	}
	return out_len;
}
