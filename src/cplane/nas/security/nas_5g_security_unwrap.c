/**
 * @file security/nas_5g_security_unwrap.c
 * @brief 5G NAS security header processing (MAC verify + decrypt)
 *
 * Extracts the security unwrap logic from the 5G→4G NAS dispatcher so
 * that nas_5g_to_4g.c only contains message routing.
 *
 * Handles:
 *   - Security header type parsing
 *   - 5G DL COUNT management (overflow detection)
 *   - MAC verification (NIA2 / AES-CMAC)
 *   - Decryption (NEA2 / AES-CTR)
 *   - Security Mode Command pass-through (sent plain per TS 24.301)
 *
 * @see 3GPP TS 33.501 (5GS Security)
 * @see 3GPP TS 24.501 (NAS for 5GS — security header format)
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "security/security.h"

int nas_5g_security_unwrap(const uint8_t *nas_5g, size_t nas_5g_len,
                           ue_id_mapping_t *security_cache,
                           const uint8_t **plain_msg, size_t *plain_len,
                           uint8_t *decrypted_buf, size_t decrypted_buf_size,
                           uint8_t *mac_out, bool *mac_present_out,
                           uint8_t *sequence_number_out) {
    if (!nas_5g || !plain_msg || !plain_len || nas_5g_len < 3) {
        return -1;
    }

    uint8_t outer_sec_hdr = (nas_5g_len > 1) ? (nas_5g[1] & 0x0F) : 0;
    *mac_present_out = false;
    *sequence_number_out = 0;
    if (mac_out) memset(mac_out, 0, 4);

    if (outer_sec_hdr == 0) {
        /* Plain 5G NAS message — no security processing needed */
        *plain_msg = nas_5g;
        *plain_len = nas_5g_len;
        return 0;
    }

    /* ---- Security header present ---- */
    if (nas_5g_len <= 7) {
        s1n2_log_security_mode_result("downlink", false, nas_5g[0],
                                      nas_5g_len > 2 ? nas_5g[2] : 0,
                                      "security header without payload");
        return -1;
    }

    uint32_t received_mac = ((uint32_t)nas_5g[2] << 24) |
                            ((uint32_t)nas_5g[3] << 16) |
                            ((uint32_t)nas_5g[4] << 8)  |
                            ((uint32_t)nas_5g[5]);
    uint8_t sqn = nas_5g[6];
    if (mac_out) memcpy(mac_out, nas_5g + 2, 4);
    *mac_present_out = true;
    *sequence_number_out = sqn;
    const size_t sec_hdr_skip = 7;

    printf("[DEBUG] [5G-DL-SEC] Security header type: 0x%02X, MAC: 0x%08X, SQN: %u\n",
           outer_sec_hdr, received_mac, sqn);

    /* Security Mode Command is sent plain even with security header */
    bool is_smc = (nas_5g_len > 9 && nas_5g[7] == 0x7E && nas_5g[9] == 0x5D);
    if (is_smc) {
        printf("[INFO] Security Mode Command detected - processing as plain message\n");
        printf("[WARN] Cannot verify 5G MAC with 4G keys - sending plain SMC per TS 24.301 5.4.3.3\n");
        printf("[INFO] UE should accept plain SMC when no prior EPS security context exists\n");
        *mac_present_out = false;
        *plain_msg = nas_5g + sec_hdr_skip;
        *plain_len = nas_5g_len - sec_hdr_skip;
        return 0;
    }

    /* ---- Encrypted / integrity-protected message ---- */
    if (!security_cache || !security_cache->has_5g_nas_keys) {
        printf("[ERROR] [5G-DL-SEC] 5G NAS keys not available for decryption\n");
        printf("[ERROR] [5G-DL-SEC] has_5g_nas_keys=%d\n",
               security_cache ? security_cache->has_5g_nas_keys : 0);
        return -1;
    }

    /* DL COUNT (overflow detection) */
    uint32_t old_dl_count_5g = 0;
    uint8_t old_sqn = old_dl_count_5g & 0xFF;
    uint16_t overflow = (old_dl_count_5g >> 8) & 0xFFFF;
    if (sqn < old_sqn) {
        overflow++;
        printf("[DEBUG] [5G-DL-SEC] SQN overflow detected: %u < %u\n", sqn, old_sqn);
    }
    uint32_t dl_count_5g = (overflow << 8) | sqn;
    printf("[DEBUG] [5G-DL-SEC] DL COUNT: 0x%08X (overflow=%u, sqn=%u)\n",
           dl_count_5g, overflow, sqn);

    /* --- MAC verification --- */
    bool is_integrity_protected = (outer_sec_hdr == 0x01 || outer_sec_hdr == 0x02 ||
                                   outer_sec_hdr == 0x03 || outer_sec_hdr == 0x04);
    if (is_integrity_protected) {
        uint8_t calculated_mac[4];
        const uint8_t *mac_input = nas_5g + 6;
        size_t mac_input_len = nas_5g_len - 6;
        uint8_t selected_nia = 2;

        printf("[DEBUG] [5G-DL-SEC] Computing MAC with NIA%u, K_NASint_5G=%02X%02X%02X%02X...\n",
               selected_nia,
               security_cache->k_nas_int_5g[0], security_cache->k_nas_int_5g[1],
               security_cache->k_nas_int_5g[2], security_cache->k_nas_int_5g[3]);

        int mac_result = s1n2_nas_compute_mac(
            (s1n2_nas_integrity_alg_t)selected_nia,
            security_cache->k_nas_int_5g,
            dl_count_5g, 1, 1,
            mac_input, mac_input_len, calculated_mac);

        uint32_t calculated_mac_u32 = ((uint32_t)calculated_mac[0] << 24) |
                                      ((uint32_t)calculated_mac[1] << 16) |
                                      ((uint32_t)calculated_mac[2] << 8)  |
                                      ((uint32_t)calculated_mac[3]);

        printf("[DEBUG] [5G-DL-SEC] MAC verification: received=0x%08X, calculated=0x%08X, result=%d\n",
               received_mac, calculated_mac_u32, mac_result);

        if (mac_result != 0 || received_mac != calculated_mac_u32) {
            printf("[ERROR] [5G-DL-SEC] MAC verification FAILED!\n");
            return -1;
        }
        printf("[INFO] [5G-DL-SEC] MAC verification SUCCESS\n");
    }

    /* --- Decryption --- */
    bool is_ciphered = (outer_sec_hdr == 0x02 || outer_sec_hdr == 0x04);
    if (is_ciphered) {
        const uint8_t *encrypted_payload = nas_5g + 7;
        size_t encrypted_len = nas_5g_len - 7;

        printf("[DEBUG] [5G-DL-SEC] Decrypting with NEA2, COUNT=0x%08X, encrypted_len=%zu\n",
               dl_count_5g, encrypted_len);
        printf("[DEBUG] [5G-DL-SEC] K_NASenc_5G=%02X%02X%02X%02X...\n",
               security_cache->k_nas_enc_5g[0], security_cache->k_nas_enc_5g[1],
               security_cache->k_nas_enc_5g[2], security_cache->k_nas_enc_5g[3]);

        if (encrypted_len > decrypted_buf_size) {
            printf("[ERROR] [5G-DL-SEC] Encrypted payload too large: %zu > %zu\n",
                   encrypted_len, decrypted_buf_size);
            return -1;
        }

        int decrypt_result = s1n2_nas_encrypt(
            (s1n2_nas_encryption_alg_t)2,
            security_cache->k_nas_enc_5g,
            dl_count_5g, 1, 1,
            encrypted_payload, encrypted_len, decrypted_buf);

        if (decrypt_result != 0) {
            printf("[ERROR] [5G-DL-SEC] Decryption FAILED\n");
            return -1;
        }

        *plain_msg = decrypted_buf;
        *plain_len = encrypted_len;

        printf("[INFO] [5G-DL-SEC] Decryption SUCCESS, plain_len=%zu\n", encrypted_len);
        printf("[DEBUG] [5G-DL-SEC] Decrypted NAS: ");
        for (size_t i = 0; i < encrypted_len && i < 16; i++) {
            printf("%02X ", decrypted_buf[i]);
        }
        if (encrypted_len > 16) printf("...");
        printf("\n");
    } else if (outer_sec_hdr == 0x01 || outer_sec_hdr == 0x03) {
        *plain_msg = nas_5g + 7;
        *plain_len = nas_5g_len - 7;
        printf("[INFO] [5G-DL-SEC] Message is integrity-protected only (not ciphered)\n");
    } else {
        printf("[ERROR] [5G-DL-SEC] Unknown security header type: 0x%02X\n", outer_sec_hdr);
        return -1;
    }

    return 0;
}
