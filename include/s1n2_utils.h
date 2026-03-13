#ifndef S1N2_UTILS_H
#define S1N2_UTILS_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lightweight CRC32 (IEEE 802.3) for logging fingerprints */
uint32_t s1n2_crc32(const uint8_t *data, size_t len);

/* BCD nibble → ASCII character ('0'-'9') */
char s1n2_bcd_digit_to_char(uint8_t nibble);

/* Decode TBCD-encoded PLMN Identity (3 bytes) into MCC/MNC strings */
void s1n2_decode_plmn_tbcd(const uint8_t *plmn, size_t len,
                           char out_mcc[4], char out_mnc[4]);

/* ASCII character → BCD nibble */
uint8_t s1n2_char_to_bcd_digit(char c);

/* Encode MCC/MNC strings into 3-byte PLMN Identity (TBCD) */
void s1n2_encode_plmn_from_strings(const char *mcc_in, const char *mnc_in,
                                   uint8_t out[3]);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_UTILS_H */
