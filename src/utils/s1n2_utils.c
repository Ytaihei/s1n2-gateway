/*
 * s1n2_utils.c – PLMN encoding/decoding and CRC32 utilities
 *
 * Extracted from s1n2_converter.c to reduce file size and clarify
 * module boundaries.  These helpers are pure functions with no
 * dependency on converter state.
 */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "s1n2_utils.h"

/* ------------------------------------------------------------------ */
/* CRC32 (IEEE 802.3) – used only for log fingerprinting              */
/* ------------------------------------------------------------------ */
uint32_t s1n2_crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = -(int)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

/* ------------------------------------------------------------------ */
/* BCD / PLMN helpers                                                 */
/* ------------------------------------------------------------------ */
char s1n2_bcd_digit_to_char(uint8_t nibble) {
    return (nibble <= 9) ? (char)('0' + nibble) : '0';
}

void s1n2_decode_plmn_tbcd(const uint8_t *plmn, size_t len,
                           char out_mcc[4], char out_mnc[4]) {
    strcpy(out_mcc, "001");
    strcpy(out_mnc, "01");
    if (!plmn || len < 3) {
        return;
    }

    uint8_t digit1 = plmn[0] & 0x0F;
    uint8_t digit2 = (plmn[0] >> 4) & 0x0F;
    uint8_t digit3 = plmn[1] & 0x0F;
    uint8_t digit4 = (plmn[1] >> 4) & 0x0F; // MNC digit 3 or 0xF
    uint8_t digit5 = plmn[2] & 0x0F;        // MNC digit 1 (per 24.301)
    uint8_t digit6 = (plmn[2] >> 4) & 0x0F; // MNC digit 2

    out_mcc[0] = s1n2_bcd_digit_to_char(digit1);
    out_mcc[1] = s1n2_bcd_digit_to_char(digit2);
    out_mcc[2] = s1n2_bcd_digit_to_char(digit3);
    out_mcc[3] = '\0';

    if (digit4 == 0x0F) {
        out_mnc[0] = s1n2_bcd_digit_to_char(digit5);
        out_mnc[1] = s1n2_bcd_digit_to_char(digit6);
        out_mnc[2] = '\0';
    } else {
        out_mnc[0] = s1n2_bcd_digit_to_char(digit5);
        out_mnc[1] = s1n2_bcd_digit_to_char(digit6);
        out_mnc[2] = s1n2_bcd_digit_to_char(digit4);
        out_mnc[3] = '\0';
    }
}

uint8_t s1n2_char_to_bcd_digit(char c) {
    return (uint8_t)((c >= '0' && c <= '9') ? (c - '0') : 0);
}

void s1n2_encode_plmn_from_strings(const char *mcc_in, const char *mnc_in, uint8_t out[3]) {
    char mcc[4] = {'0','0','0','\0'};
    size_t lmcc = mcc_in ? strlen(mcc_in) : 0;
    if (lmcc >= 3) {
        mcc[0] = mcc_in[lmcc - 3];
        mcc[1] = mcc_in[lmcc - 2];
        mcc[2] = mcc_in[lmcc - 1];
    } else if (lmcc == 2) {
        mcc[1] = mcc_in[0];
        mcc[2] = mcc_in[1];
    } else if (lmcc == 1) {
        mcc[2] = mcc_in[0];
    }

    char mnc[4] = {'\0','\0','\0','\0'};
    size_t lmnc = mnc_in ? strlen(mnc_in) : 0;
    if (lmnc >= 3) {
        mnc[0] = mnc_in[lmnc - 3];
        mnc[1] = mnc_in[lmnc - 2];
        mnc[2] = mnc_in[lmnc - 1];
    } else if (lmnc == 2) {
        mnc[0] = mnc_in[0];
        mnc[1] = mnc_in[1];
    } else if (lmnc == 1) {
        mnc[0] = mnc_in[0];
        mnc[1] = '0';
    }

    uint8_t mcc1 = s1n2_char_to_bcd_digit(mcc[0]);
    uint8_t mcc2 = s1n2_char_to_bcd_digit(mcc[1]);
    uint8_t mcc3 = s1n2_char_to_bcd_digit(mcc[2]);
    uint8_t mnc1 = s1n2_char_to_bcd_digit(mnc[0]);
    uint8_t mnc2 = s1n2_char_to_bcd_digit(mnc[1]);
    uint8_t mnc3 = (lmnc >= 3) ? s1n2_char_to_bcd_digit(mnc[2]) : 0x0F;

    out[0] = (uint8_t)((mcc2 << 4) | mcc1);
    out[1] = (uint8_t)((mnc3 << 4) | mcc3);
    out[2] = (uint8_t)((mnc2 << 4) | mnc1);
}
