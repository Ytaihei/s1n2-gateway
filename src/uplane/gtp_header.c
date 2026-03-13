/**
 * @file gtp_header.c
 * @brief GTP-U header parse / build primitives
 *
 * Wireshark trace: GTP-U header fields (Version, Message Type, TEID)
 */
#include <stdint.h>
#include <stddef.h>

#include "gtp_header.h"

int s1n2_parse_gtpu_header(uint8_t *data, size_t len, uint32_t *teid, uint8_t *message_type) {
    if (len < 8) {
        return -1; /* Too short */
    }

    if ((data[0] & 0xF0) != 0x30) { /* Version=1, Protocol=1 */
        return -1; /* Invalid GTP-U header */
    }

    *message_type = data[1];
    *teid = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

    return 0;
}

int s1n2_build_gtpu_header(uint8_t *data, size_t len, uint32_t teid, uint8_t message_type) {
    if (len < 8) {
        return -1; /* Too short */
    }

    data[0] = 0x30; /* Version=1, Protocol=1, Extension=0, Seq=0, N-PDU=0 */
    data[1] = message_type;
    data[2] = 0x00; /* Length (will be set by caller) */
    data[3] = 0x00; /* Length (will be set by caller) */
    data[4] = (teid >> 24) & 0xFF;
    data[5] = (teid >> 16) & 0xFF;
    data[6] = (teid >> 8) & 0xFF;
    data[7] = teid & 0xFF;

    return 0;
}

