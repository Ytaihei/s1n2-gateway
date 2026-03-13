/**
 * @file shared/nas_logging.c
 * @brief Logging utilities for NAS conversion modules
 *
 * Contains logging functions for debugging NAS message conversion,
 * including hex dumps, PCO entry logging, and security mode results.
 *
 * Extracted from nas_helpers.c during Phase 1 refactoring.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"

/* ================================================================
 * Logging helpers
 * ================================================================ */

void s1n2_dump_hex(const char *tag, const uint8_t *buf, size_t len) {
	if (!tag || !buf) {
		return;
	}
	printf("[TRACE] %s (len=%zu)\n", tag, len);
	for (size_t i = 0; i < len; ++i) {
		if (i % 16 == 0) printf("  %04zu : ", i);
		printf("%02X ", buf[i]);
		if (i % 16 == 15 || i + 1 == len) printf("\n");
	}
}

void s1n2_log_pco_entries(const char *tag, const uint8_t *pco, size_t pco_len) {
	if (!pco || pco_len == 0) {
		printf("[TRACE] %s: no PCO payload\n", tag ? tag : "[PCO]");
		return;
	}
	s1n2_dump_hex(tag ? tag : "[PCO]", pco, pco_len);
	size_t pos = 0;
	while (pos < pco_len) {
		if (pco_len - pos < 2) {
			printf("[TRACE] %s: truncated entry at offset %zu\n", tag, pos);
			break;
		}
		bool is_protocol = (pco[pos] & 0x80) != 0;
		if (is_protocol) {
			if (pco_len - pos < 3) {
				printf("[TRACE] %s: protocol entry truncated at offset %zu\n", tag, pos);
				break;
			}
			uint16_t proto_id = ((uint16_t)pco[pos] << 8) | pco[pos + 1];
			uint8_t payload_len = pco[pos + 2];
			printf("[TRACE]   PCO Protocol 0x%04X (len=%u)\n", proto_id, payload_len);
			pos += 3;
			if (pos + payload_len > pco_len) {
				printf("[TRACE]     -> payload truncated (remain=%zu)\n", pco_len - pos);
				break;
			}
			pos += payload_len;
		} else {
			uint8_t container_id = pco[pos];
			uint8_t payload_len = pco[pos + 1];
			pos += 2;
			printf("[TRACE]   PCO Container 0x%02X (len=%u)\n", container_id, payload_len);
			if (pos + payload_len > pco_len) {
				printf("[TRACE]     -> payload truncated (remain=%zu)\n", pco_len - pos);
				break;
			}
			if (container_id == 0x1A && payload_len == 1) {
				printf("[WARN]   Detected 5GS PDU Session Identity inside EPS PCO (value=%u)\n", pco[pos]);
			}
			pos += payload_len;
		}
	}
}

void s1n2_log_security_mode_result(const char *direction,
								   bool success,
								   uint8_t pd,
								   uint8_t msg_type,
								   const char *details) {
	if (success) {
		if (details && *details) {
			printf("[INFO] Security Mode %s conversion succeeded (PD=0x%02X, type=0x%02X, %s)\n",
				   direction, pd, msg_type, details);
		} else {
			printf("[INFO] Security Mode %s conversion succeeded (PD=0x%02X, type=0x%02X)\n",
				   direction, pd, msg_type);
		}
	} else {
		if (details && *details) {
			printf("[WARN] Security Mode %s conversion failed (PD=0x%02X, type=0x%02X, %s)\n",
				   direction, pd, msg_type, details);
		} else {
			printf("[WARN] Security Mode %s conversion failed (PD=0x%02X, type=0x%02X)\n",
				   direction, pd, msg_type);
		}
	}
	fflush(stdout);
}
