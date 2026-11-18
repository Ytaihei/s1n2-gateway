#include "internal/s1n2_converter_internal.h"
#include "security/security.h"
#include "s1n2_log.h"

int nas_4g_security_unwrap(s1n2_context_t *ctx, ue_id_mapping_t *ue_map,
    const uint8_t *nas_buf, size_t nas_len, uint8_t *decrypted_nas_buf,
    size_t decrypted_capacity, const uint8_t **plain, size_t *plain_len) {
    if (!nas_buf || !nas_len || !plain || !plain_len || !decrypted_nas_buf || decrypted_capacity < 6) return -1;
    uint8_t nas_initial_security = (nas_buf[0] >> 4) & 0x0f;
    const uint8_t *processed_nas_buf = nas_buf;
    size_t processed_nas_len = nas_len;
    if (ue_map && !ue_map->has_nas_keys) {
        if (s1n2_try_derive_4g_nas_keys(ctx, ue_map) == 0) {
            LOG_INFO("[NAS-SEC-UL] NAS keys were derived pre-emptively before security checks\n");

        }
    }

    if (ue_map && nas_len > 6) {
        // Security header type is in the UPPER 4 bits, not lower 4 bits!
        // TS 24.301 Section 9.3.1: Security header type (bits 5-8) | Protocol discriminator (bits 1-4)
        uint8_t security_header_type = nas_initial_security;

        LOG_DEBUG("[NAS-SEC-UL] Security header type: 0x%02X (first_byte=0x%02X)\n",
               security_header_type, nas_buf[0]);

        // Security header type values:
        // 0x00: Plain NAS message (no security)
        // 0x01: Integrity protected
        // 0x02: Integrity protected and ciphered
        // 0x03: Integrity protected with new EPS security context
        // 0x04: Integrity protected and ciphered with new EPS security context

        bool is_integrity_protected = false;
        bool is_ciphered = false;
        bool is_new_security_context = false;
        bool security_header_removed = false;

        if (security_header_type == 0x01 || security_header_type == 0x03) {
            is_integrity_protected = true;
        } else if (security_header_type == 0x02 || security_header_type == 0x04) {
            is_integrity_protected = true;
            is_ciphered = true;
        }

        if (security_header_type == 0x03 || security_header_type == 0x04) {
            is_new_security_context = true;
        }

        if (is_integrity_protected || is_ciphered) {
            if (!ue_map->has_nas_keys) {
                LOG_WARN("[NAS-SEC-UL] Encrypted/integrity-protected message received but no NAS keys available\n");

                if (!is_ciphered && nas_len > 6) {
                    processed_nas_buf = nas_buf + 6;
                    processed_nas_len = nas_len - 6;
                    security_header_removed = true;
                }
            } else {
                // Extract security header fields
                uint32_t received_mac = ((uint32_t)nas_buf[1] << 24) |
                                      ((uint32_t)nas_buf[2] << 16) |
                                      ((uint32_t)nas_buf[3] << 8) |
                                      ((uint32_t)nas_buf[4]);
                uint8_t sequence_number = nas_buf[5];

                LOG_DEBUG("[NAS-SEC-UL] Received MAC: 0x%08X, SQN: %u\n", received_mac, sequence_number);

                // Update UL COUNT (handle overflow)
                // UL COUNT structure: overflow (8 bits) | sequence number (8 bits) = 16 bits used
                // Note: 4G uses 8-bit sequence number, not 24-bit like 5G
                uint32_t old_ul_count = ue_map->nas_ul_count;
                uint8_t old_sqn = old_ul_count & 0xFF;
                uint8_t overflow = (old_ul_count >> 8) & 0xFF;

                if (is_new_security_context) {
                    // Reset UL COUNT for new security context
                    ue_map->nas_ul_count = 0;
                    overflow = 0;
                    LOG_DEBUG("[NAS-SEC-UL] New security context - reset UL COUNT to 0\n");
                } else {
                    // Check for sequence number overflow
                    if (sequence_number < old_sqn) {
                        overflow++;
                        LOG_DEBUG("[NAS-SEC-UL] SQN overflow detected: %u < %u, overflow=%u\n",
                               sequence_number, old_sqn, overflow);
                    }
                    ue_map->nas_ul_count = (overflow << 8) | sequence_number;
                }

                LOG_DEBUG("[NAS-SEC-UL] UL COUNT: 0x%08X (overflow=%u, sqn=%u)\n",
                       ue_map->nas_ul_count, overflow, sequence_number);

                // MAC verification (if integrity protected)
                if (is_integrity_protected) {
                    uint8_t selected_eia = ue_map->selected_nas_security_alg & 0x07;
                    if (selected_eia == S1N2_NAS_EIA0) {
                        LOG_INFO("[NAS-SEC-UL] EIA0 negotiated - skipping MAC verification and treating payload as plain\n");
                        if (nas_len > 6) {
                            processed_nas_buf = nas_buf + 6;
                            processed_nas_len = nas_len - 6;
                            security_header_removed = true;
                        }
                    } else {
                        uint8_t calculated_mac[4];

                        const uint8_t *mac_input = nas_buf + 5;
                        size_t mac_input_len = nas_len - 5;

                        LOG_INFO(" (len=%zu)\n", mac_input_len);

                        int mac_result = s1n2_nas_compute_mac(
                            (s1n2_nas_integrity_alg_t)selected_eia,
                            ue_map->k_nas_int,
                            ue_map->nas_ul_count,
                            0,
                            0,
                            mac_input,
                            mac_input_len,
                            calculated_mac
                        );

                        uint32_t calculated_mac_u32 = ((uint32_t)calculated_mac[0] << 24) |
                                                     ((uint32_t)calculated_mac[1] << 16) |
                                                     ((uint32_t)calculated_mac[2] << 8) |
                                                     ((uint32_t)calculated_mac[3]);

                        LOG_DEBUG("[NAS-SEC-UL] MAC verification: received=0x%08X, calculated=0x%08X, result=%d\n",
                               received_mac, calculated_mac_u32, mac_result);

                        if (mac_result != 0 || received_mac != calculated_mac_u32) {
                            uint8_t tentative_type = (nas_len > 7) ? nas_buf[7] : 0x00;
                            bool auth_failure_bypass = (tentative_type == 0x5C);
                            LOG_ERROR("[NAS-SEC-UL] MAC verification FAILED!%s\n",
                                   auth_failure_bypass ? " (bypassing for Auth Failure)" : "");

                            if (!auth_failure_bypass) {

                                return -1;
                            }
                        } else {
                            LOG_INFO("[NAS-SEC-UL] MAC verification SUCCESS\n");
                        }
                    }
                }

                // Decryption (if ciphered)
                if (is_ciphered) {
                    uint8_t selected_eea = (ue_map->selected_nas_security_alg >> 4) & 0x07;

                    // Security header structure per TS 24.301 Section 9.3.1:
                    // [Header type + PD (1)] [MAC (4)] [SQN (1)] [Encrypted payload (...)]
                    // SQN is NOT encrypted, only the payload after SQN is encrypted
                    // Skip security header (6 bytes: type+MAC+SQN) to get to encrypted payload
                    const uint8_t *encrypted_payload = nas_buf + 6;
                    size_t encrypted_len = nas_len - 6;

                    if (encrypted_len > decrypted_capacity - 6) {
                        LOG_ERROR("[NAS-SEC-UL] Encrypted payload too large\n");

                        return -1;
                    }

                    // Decrypt the payload (in-place decryption into decrypted_nas_buf)
                    int decrypt_result = s1n2_nas_encrypt(
                        (s1n2_nas_encryption_alg_t)selected_eea,
                        ue_map->k_nas_enc,
                        ue_map->nas_ul_count,
                        0,  // bearer
                        0,  // direction (0 = uplink)
                        encrypted_payload,
                        encrypted_len,
                        decrypted_nas_buf + 6  // Write decrypted data starting at offset 6
                    );

                    if (decrypt_result != 0) {
                        LOG_ERROR("[NAS-SEC-UL] Decryption FAILED\n");

                        return -1;
                    }

                    // Copy the unencrypted part (security header: type + MAC + SQN)
                    memcpy(decrypted_nas_buf, nas_buf, 6);

                    // Update to use decrypted buffer, skip security header (6 bytes)
                    // The plain NAS message (EMM/ESM header + payload) starts at byte 6
                    processed_nas_buf = decrypted_nas_buf + 6;
                    processed_nas_len = nas_len - 6;

                    LOG_INFO("[NAS-SEC-UL] Decryption SUCCESS, plain NAS length: %zu\n", processed_nas_len);

                    security_header_removed = true;
                } else {
                    // Integrity only - skip security header (6 bytes)
                    processed_nas_buf = nas_buf + 6;
                    processed_nas_len = nas_len - 6;
                    security_header_removed = true;
                    LOG_DEBUG("[NAS-SEC-UL] Integrity only - skipped 6-byte security header\n");
                }
            }
        } else {
            LOG_DEBUG("[NAS-SEC-UL] Plain NAS message (no security)\n");
        }

        if (!security_header_removed && is_integrity_protected && !is_ciphered && nas_len > 6) {
            processed_nas_buf = nas_buf + 6;
            processed_nas_len = nas_len - 6;
        }
    } else if (!ue_map && nas_initial_security != 0) {
        LOG_WARN("[NAS-SEC-UL] Security header type 0x%02X present but UE mapping missing; cannot verify/decrypt\n",
               nas_initial_security);

    }

    *plain = processed_nas_buf;
    *plain_len = processed_nas_len;
    return 0;
}
