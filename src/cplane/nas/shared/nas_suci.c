#include "suci_utils.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static inline char ensure_digit(char c) {
    return (c >= '0' && c <= '9') ? c : '0';
}

static void sanitize_digit_block(const char *src, size_t count, char *dst) {
    for (size_t i = 0; i < count; ++i) {
        char c = src ? src[i] : '\0';
        dst[i] = ensure_digit(c);
    }
    dst[count] = '\0';
}

static size_t encode_digits_to_bcd(const char *digits, size_t digits_len,
                                   uint8_t *out, size_t out_capacity) {
    if (!out || out_capacity == 0) return 0;

    size_t bytes_written = 0;
    size_t index = 0;
    while (index < digits_len) {
        if (bytes_written >= out_capacity) {
            return 0; // insufficient space
        }

        uint8_t low = (uint8_t)(ensure_digit(digits[index]) - '0');
        index++;

        uint8_t high = 0x0F;
        if (index < digits_len) {
            high = (uint8_t)(ensure_digit(digits[index]) - '0');
            index++;
        }

        out[bytes_written++] = (uint8_t)(((high & 0x0F) << 4) | (low & 0x0F));
    }
    return bytes_written;
}

static void encode_routing_indicator(const char *routing_digits, uint8_t out[2]) {
    // TS 24.501: Null routing indicator is 0x0000, not 0xFFFF
    out[0] = 0x00;
    out[1] = 0x00;

    if (!routing_digits || !*routing_digits) {
        return;
    }

    size_t nibble_index = 0;
    for (size_t i = 0; routing_digits[i] != '\0' && nibble_index < 4; ++i) {
        if (!isdigit((unsigned char)routing_digits[i])) {
            continue;
        }
        uint8_t digit = (uint8_t)(routing_digits[i] - '0');
        size_t byte_index = nibble_index / 2;
        if ((nibble_index % 2) == 0) {
            out[byte_index] = (uint8_t)((out[byte_index] & 0xF0) | digit);
        } else {
            out[byte_index] = (uint8_t)((out[byte_index] & 0x0F) | (digit << 4));
        }
        nibble_index++;
    }
}

size_t decode_imsi_digits_from_eps_mobile_identity(const uint8_t *mobile_identity,
                                                   size_t mobile_identity_len,
                                                   char *imsi_digits,
                                                   size_t imsi_digits_size) {
    if (!mobile_identity || !imsi_digits || imsi_digits_size == 0 || mobile_identity_len == 0) {
        return 0;
    }

    size_t out_index = 0;
    memset(imsi_digits, 0, imsi_digits_size);

    uint8_t first_octet = mobile_identity[0];
    uint8_t identity_type = first_octet & 0x07;
    if (identity_type != 0x01) {
        // Currently only IMSI is supported.
        return 0;
    }

    uint8_t first_digit = (first_octet >> 4) & 0x0F;
    if (first_digit <= 9) {
        if (out_index + 1 >= imsi_digits_size) return 0;
        imsi_digits[out_index++] = (char)('0' + first_digit);
    }

    for (size_t i = 1; i < mobile_identity_len; ++i) {
        uint8_t byte = mobile_identity[i];
        uint8_t low = byte & 0x0F;
        uint8_t high = (byte >> 4) & 0x0F;

        if (low <= 9) {
            if (out_index + 1 >= imsi_digits_size) return 0;
            imsi_digits[out_index++] = (char)('0' + low);
        }
        if (high <= 9) {
            if (out_index + 1 >= imsi_digits_size) return 0;
            imsi_digits[out_index++] = (char)('0' + high);
        }
    }

    if (out_index < imsi_digits_size) {
        imsi_digits[out_index] = '\0';
    } else {
        imsi_digits[imsi_digits_size - 1] = '\0';
    }

    return out_index;
}

int suci_build_from_imsi_digits(const char *imsi_digits,
                                size_t imsi_len,
                                const suci_builder_config_t *cfg,
                                uint8_t *suci_out,
                                size_t *suci_len) {
    if (!imsi_digits || !suci_out || !suci_len || *suci_len == 0) {
        return -1;
    }

    suci_builder_config_t local_cfg = {0};
    if (cfg) {
        local_cfg = *cfg;
    }

    if (local_cfg.mnc_len <= 0 && local_cfg.mnc[0] != '\0') {
        size_t len = strlen(local_cfg.mnc);
        if (len == 2 || len == 3) {
            local_cfg.mnc_len = (int)len;
        }
    }

    if (local_cfg.mnc_len != 2 && local_cfg.mnc_len != 3) {
        if (imsi_len >= 6) {
            local_cfg.mnc_len = 3;
        } else if (imsi_len >= 5) {
            local_cfg.mnc_len = 2;
        } else {
            local_cfg.mnc_len = 3;
        }
    }

    if (local_cfg.mnc_len != 2 && local_cfg.mnc_len != 3) {
        return -1;
    }

    char mcc_digits[4] = { '0', '0', '1', '\0' };
    if (imsi_len >= 3) {
        sanitize_digit_block(imsi_digits, 3, mcc_digits);
    } else if (local_cfg.mcc[0] != '\0') {
        size_t len = strlen(local_cfg.mcc);
        const char *src = local_cfg.mcc;
        if (len > 3) src += len - 3;
        sanitize_digit_block(src, 3, mcc_digits);
    }

    char mnc_digits[4] = { '0', '1', '\0', '\0' };
    if (imsi_len >= 3 + (size_t)local_cfg.mnc_len) {
        sanitize_digit_block(imsi_digits + 3, (size_t)local_cfg.mnc_len, mnc_digits);
    } else if (local_cfg.mnc[0] != '\0') {
        size_t len = strlen(local_cfg.mnc);
        const char *src = local_cfg.mnc;
        if (len > (size_t)local_cfg.mnc_len) src += len - local_cfg.mnc_len;
        sanitize_digit_block(src, (size_t)local_cfg.mnc_len, mnc_digits);
    } else {
        sanitize_digit_block("01", (size_t)local_cfg.mnc_len, mnc_digits);
    }

    size_t msin_start = 3 + (size_t)local_cfg.mnc_len;
    size_t msin_len = (imsi_len > msin_start) ? (imsi_len - msin_start) : 0;
    char msin_digits[16] = {0};
    if (msin_len > 0) {
        if (msin_len > sizeof(msin_digits) - 1) msin_len = sizeof(msin_digits) - 1;
        sanitize_digit_block(imsi_digits + msin_start, msin_len, msin_digits);
    } else {
        msin_len = 1;
        msin_digits[0] = '0';
        msin_digits[1] = '\0';
    }

    size_t required_capacity = 8 + (msin_len + 1) / 2;
    if (*suci_len < required_capacity) {
        return -1;
    }

    uint8_t header = 0;
    uint8_t suci_type = 0x01; // SUCI
    uint8_t odd_even = (msin_len % 2) ? 1 : 0;
    uint8_t supi_format = 0x00; // IMSI
    header |= (uint8_t)((supi_format & 0x0F) << 4);
    header |= (uint8_t)((odd_even & 0x01) << 3);
    header |= (uint8_t)(suci_type & 0x07);

    uint8_t plmn[3];
    int mcc1 = mcc_digits[0] - '0';
    int mcc2 = mcc_digits[1] - '0';
    int mcc3 = mcc_digits[2] - '0';

    int mnc1 = mnc_digits[0] - '0';
    int mnc2 = (local_cfg.mnc_len >= 2) ? (mnc_digits[1] - '0') : 0;
    int mnc3 = (local_cfg.mnc_len == 3) ? (mnc_digits[2] - '0') : 0x0F;

    plmn[0] = (uint8_t)(((mcc2 & 0x0F) << 4) | (mcc1 & 0x0F));
    plmn[1] = (uint8_t)(((mnc3 & 0x0F) << 4) | (mcc3 & 0x0F));
    plmn[2] = (uint8_t)(((mnc2 & 0x0F) << 4) | (mnc1 & 0x0F));

    uint8_t routing_bcd[2];
    encode_routing_indicator(local_cfg.routing_indicator, routing_bcd);

    uint8_t protection_scheme_id = (uint8_t)(local_cfg.protection_scheme_id & 0x0F);
    uint8_t home_pki_value = local_cfg.home_network_pki_value;

    uint8_t msin_bcd[16];
    size_t msin_bytes = encode_digits_to_bcd(msin_digits, msin_len, msin_bcd, sizeof(msin_bcd));
    if (msin_bytes == 0 && msin_len > 0) {
        return -1;
    }

    size_t offset = 0;
    suci_out[offset++] = header;
    memcpy(&suci_out[offset], plmn, sizeof(plmn));
    offset += sizeof(plmn);
    suci_out[offset++] = routing_bcd[0];
    suci_out[offset++] = routing_bcd[1];
    suci_out[offset++] = (uint8_t)(protection_scheme_id & 0x0F);
    suci_out[offset++] = home_pki_value;

    memcpy(&suci_out[offset], msin_bcd, msin_bytes);
    offset += msin_bytes;

    *suci_len = offset;
    return 0;
}

int suci_build_from_eps_mobile_identity(const uint8_t *mobile_identity,
                                        size_t mobile_identity_len,
                                        const suci_builder_config_t *cfg,
                                        uint8_t *suci_out,
                                        size_t *suci_len,
                                        char *imsi_digits_out,
                                        size_t imsi_digits_out_len) {
    if (!mobile_identity || mobile_identity_len == 0) {
        return -1;
    }

    char decoded_imsi[32];
    size_t digits = decode_imsi_digits_from_eps_mobile_identity(
        mobile_identity, mobile_identity_len, decoded_imsi, sizeof(decoded_imsi));
    if (digits == 0) {
        return -1;
    }

    if (imsi_digits_out && imsi_digits_out_len > 0) {
        strncpy(imsi_digits_out, decoded_imsi, imsi_digits_out_len - 1);
        imsi_digits_out[imsi_digits_out_len - 1] = '\0';
    }

    return suci_build_from_imsi_digits(decoded_imsi, digits, cfg, suci_out, suci_len);
}
