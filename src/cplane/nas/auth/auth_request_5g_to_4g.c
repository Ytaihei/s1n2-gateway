#include "s1n2_log.h"
/**
 * @file auth/auth_request_5g_to_4g.c
 * @brief 5G Authentication Request (0x56) → 4G Authentication Request (0x52)
 *
 * Extracts RAND and AUTN from 5G Authentication Request and builds
 * the corresponding 4G EMM Authentication Request message.
 *
 * Extracted from nas_5g_to_4g.c case 0x56 during Phase 2 refactoring.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "auth/auth.h"

int auth_request_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                  uint8_t *nas_4g, size_t *nas_4g_len) {
	if (!msg || !nas_4g || !nas_4g_len || msg_len < 3) {
		return -1;
	}

	size_t offset = 3;
	if (offset >= msg_len) {
		LOG_WARN("5G NAS-PDU too short for ngKSI\n");
		return -1;
	}
	uint8_t ngksi = msg[offset++];

	if (offset >= msg_len) {
		LOG_WARN("5G NAS-PDU missing payload after ngKSI\n");
		return -1;
	}

	if (offset < msg_len) {
		uint8_t tag = msg[offset];
		if (tag == 0x38) {
			offset++;
			if (offset >= msg_len) {
				LOG_WARN("5G NAS-PDU truncated within ABBA IEI\n");
				return -1;
			}
			uint8_t abba_len = msg[offset++];
			if (offset + abba_len > msg_len) {
				LOG_WARN("5G NAS-PDU truncated within ABBA contents\n");
				return -1;
			}
			offset += abba_len;
		} else if (tag < 0x20) {
			uint8_t abba_len = tag;
			offset++;
			if (offset + abba_len > msg_len) {
				LOG_WARN("5G NAS-PDU truncated within implicit ABBA contents\n");
				return -1;
			}
			offset += abba_len;
		}
	}

	if (offset >= msg_len || msg[offset] != 0x21) {
		LOG_WARN("5G NAS-PDU missing Authentication Parameter RAND IE (expected IEI 0x21)\n");
		return -1;
	}
	offset++;
	if (offset + 16 > msg_len) {
		LOG_WARN("5G NAS-PDU truncated while reading RAND\n");
		return -1;
	}
	uint8_t rand_value[16];
	memcpy(rand_value, msg + offset, sizeof(rand_value));
	offset += sizeof(rand_value);

	if (offset >= msg_len || msg[offset] != 0x20) {
		LOG_WARN("5G NAS-PDU missing Authentication Parameter AUTN IE (expected IEI 0x20)\n");
		return -1;
	}
	offset++;
	if (offset >= msg_len) {
		LOG_WARN("5G NAS-PDU truncated before AUTN length\n");
		return -1;
	}
	uint8_t autn_len = msg[offset++];
	if (autn_len != 16) {
		LOG_WARN("Unexpected AUTN length %u (expected 16)\n", autn_len);
		return -1;
	}
	if (offset + autn_len > msg_len) {
		LOG_WARN("5G NAS-PDU truncated while reading AUTN\n");
		return -1;
	}
	uint8_t autn_value[16];
	memcpy(autn_value, msg + offset, autn_len);
	offset += autn_len;

	size_t required_len = 3 + sizeof(rand_value) + 1 + autn_len;
	if (*nas_4g_len < required_len) {
		LOG_WARN("Output buffer too small for 4G Authentication Request (need %zu)\n", required_len);
		return -1;
	}

	size_t out_off = 0;
	nas_4g[out_off++] = 0x07;
	nas_4g[out_off++] = 0x52;
	nas_4g[out_off++] = ngksi;
	memcpy(nas_4g + out_off, rand_value, sizeof(rand_value));
	out_off += sizeof(rand_value);
	nas_4g[out_off++] = autn_len;
	memcpy(nas_4g + out_off, autn_value, autn_len);
	out_off += autn_len;

	LOG_TRACE("Built 4G Authentication Request (len=%zu, RAND_len=16, AUTN_len=%u)\n", out_off, autn_len);

	*nas_4g_len = out_off;

	LOG_INFO("5G Authentication Request converted to 4G (len=%zu)\n", *nas_4g_len);

	return 0;
}
