#include "gtp_header.h"

/* Validate every length before dereferencing. Extension lengths include their
 * length byte and next-type byte, in units of four octets (TS 29.281). */
int s1n2_gtpu_payload_offset(const uint8_t *data, size_t len, size_t *offset) {
    if (!data || !offset || len < 8 || (data[0] & 0xf0) != 0x30) return -1;
    size_t declared = ((size_t)data[2] << 8) | data[3];
    if (declared != len - 8) return -1;
    size_t pos = 8;
    uint8_t next = 0;
    if (data[0] & 7) {
        if (len < 12) return -1;
        pos = 12;
        if (data[0] & 4) next = data[11];
    }
    while (next) {
        if (pos >= len) return -1;
        size_t extension_len = (size_t)data[pos] * 4;
        if (!extension_len || extension_len > len - pos) return -1;
        next = data[pos + extension_len - 1];
        pos += extension_len;
    }
    *offset = pos;
    return 0;
}

int s1n2_parse_gtpu_header(uint8_t *data, size_t len, uint32_t *teid, uint8_t *message_type) {
    size_t offset;
    if (!teid || !message_type || s1n2_gtpu_payload_offset(data, len, &offset)) return -1;
    *message_type = data[1];
    *teid = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
            ((uint32_t)data[6] << 8) | data[7];
    return 0;
}

int s1n2_build_gtpu_header(uint8_t *data, size_t len, uint32_t teid, uint8_t message_type) {
    if (!data || len < 8) return -1;
    data[0] = 0x30;
    data[1] = message_type;
    data[2] = data[3] = 0;
    data[4] = (uint8_t)(teid >> 24);
    data[5] = (uint8_t)(teid >> 16);
    data[6] = (uint8_t)(teid >> 8);
    data[7] = (uint8_t)teid;
    return 0;
}
