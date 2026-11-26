/**
 * @file security/security.h
 * @brief Public API for Security Mode module
 *
 * Provides functions for converting 4G/5G Security Mode messages:
 *   - SMC (5G→4G): 5G Security Mode Command → 4G Security Mode Command
 *   - SMC Complete (4G→5G): 4G Security Mode Complete → 5G Security Mode Complete
 *   - Shared: 5G uplink MAC computation, algorithm mapping tables
 *
 * Created during Phase 3 NAS modularization.
 *
 * @warning This module handles security-critical code:
 *   - DL COUNT initialization (must be 0 when sending SMC)
 *   - UL COUNT increment (must happen AFTER MAC computation)
 *   - KeNB derivation (must happen AFTER SMC Complete)
 *   - Registration Request piggybacking (IEI 0x71, TS 24.501 § 8.2.28)
 *
 * @see 3GPP TS 24.301 (NAS for EPS)
 * @see 3GPP TS 24.501 (NAS for 5GS)
 * @see 3GPP TS 33.401 / TS 33.501 (Security)
 */
#ifndef S1N2_SECURITY_MODULE_H
#define S1N2_SECURITY_MODULE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Forward declarations — avoid pulling heavyweight headers */
typedef struct s1n2_context          s1n2_context_t;
typedef struct ue_id_mapping         ue_id_mapping_t;
/* s1n2_security_mode_info_t is defined in s1n2_converter.h (anonymous struct).
 * Callers that use smc_convert_5g_to_4g() must include s1n2_converter.h. */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Derive 4G NAS keys (K_NAS_int, K_NAS_enc) for a UE.
 *
 * Uses cached RAND/AUTN/SQN^AK and subscriber Ki/OPc to derive
 * KASME and then NAS integrity/encryption keys.
 *
 * @param ctx     Converter context (for auth_ctx subscription keys)
 * @param ue_map  UE mapping with cached RAND, AUTN, IMSI
 * @return 0 on success, -1 on failure
 */
int s1n2_try_derive_4g_nas_keys(s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/* EPS NAS protection processing, independent of the S1AP envelope. */
int nas_4g_security_unwrap(s1n2_context_t *ctx, ue_id_mapping_t *ue_map,
    const uint8_t *nas_buf, size_t nas_len, uint8_t *decrypted_buf,
    size_t decrypted_capacity, const uint8_t **plain, size_t *plain_len);

/**
 * @brief Unwrap 5G NAS security header (MAC verify + decrypt)
 *
 * Processes 5G DL NAS security header: verifies MAC and decrypts
 * payload using the negotiated NIA/NEA.  Returns pointer to plain NAS message.  For Security
 * Mode Command, returns the message as-is (plain pass-through).
 *
 * @param nas_5g              Input 5G NAS PDU
 * @param nas_5g_len          Length of input
 * @param security_cache      UE mapping with 5G NAS keys
 * @param plain_msg           [out] Pointer to plain NAS message
 * @param plain_len           [out] Length of plain NAS message
 * @param decrypted_buf       Caller-provided buffer for decrypted payload
 * @param decrypted_buf_size  Size of decrypted_buf
 * @param mac_out             [out] 4-byte MAC from security header (may be NULL)
 * @param mac_present_out     [out] Whether MAC was present
 * @param sequence_number_out [out] Sequence number from header
 * @return 0 on success, -1 on error
 */
int nas_5g_security_unwrap(const uint8_t *nas_5g, size_t nas_5g_len,
                           ue_id_mapping_t *security_cache,
                           const uint8_t **plain_msg, size_t *plain_len,
                           uint8_t *decrypted_buf, size_t decrypted_buf_size,
                           uint8_t *mac_out, bool *mac_present_out,
                           uint8_t *sequence_number_out);

/**
 * @brief Convert 5G Security Mode Command (0x5D) to 4G Security Mode Command
 *
 * Parses 5G NAS security algorithms, ngKSI, UE security capability,
 * maps NEA→EEA / NIA→EIA, and builds 4G Security Mode Command with
 * optional integrity protection (MAC).
 *
 * @warning Initializes DL COUNT to 0 when security context is available.
 *
 * @param payload        Inner 5G NAS message (after security header stripping)
 * @param payload_len    Length of payload
 * @param nas_4g         Output buffer for 4G NAS
 * @param nas_4g_len     In: capacity, Out: actual length
 * @param info           Security mode info struct to populate (may be NULL)
 * @param mac            5G MAC from outer security header (NULL if not present)
 * @param mac_present    Whether MAC was present in outer header
 * @param seq_no         Sequence number from outer security header
 * @param security_cache UE mapping with security context (const, but DL COUNT reset)
 * @return 0 on success, -1 on error
 */
int smc_convert_5g_to_4g(const uint8_t *payload, size_t payload_len,
                         uint8_t *nas_4g, size_t *nas_4g_len,
                         s1n2_security_mode_info_t *info,
                         const uint8_t *mac, bool mac_present,
                         uint8_t seq_no,
                         const ue_id_mapping_t *security_cache);

/**
 * @brief Convert 4G Security Mode Complete (0x5E) to 5G Security Mode Complete
 *
 * Parses 4G SMC Complete IEs, builds 5G SMC Complete with:
 *   - IMEISV remapping (IEI 0x23 → 0x77)
 *   - NAS message container (IEI 0x71) with piggybacked Registration Request
 *   - 5G integrity protection (MAC computation)
 *   - KeNB derivation from KASME
 *
 * @warning Security-critical:
 *   - UL COUNT incremented AFTER MAC computation
 *   - KeNB derived AFTER SMC Complete processing
 *   - Registration Request piggybacking must be preserved
 *
 * @param nas_4g         Input 4G NAS message
 * @param nas_4g_len     Length of input
 * @param first_byte     First byte of 4G NAS (PD + security header)
 * @param msg_type       Message type (0x5E)
 * @param payload_offset Offset to message payload (after PD+msg_type)
 * @param nas_5g         Output buffer for 5G NAS
 * @param nas_5g_len     In: capacity, Out: actual length
 * @param ctx            Converter context
 * @param ue_map         UE mapping with security context
 * @return 0 on success, -1 on error
 */
int smc_complete_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                  uint8_t first_byte, uint8_t msg_type,
                                  size_t payload_offset,
                                  uint8_t *nas_5g, size_t *nas_5g_len,
                                  s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/**
 * @brief Compute 5G uplink NAS MAC for integrity protection
 *
 * Calculates MAC-I using K_NASint_5G (preferred) or K_NASint_4G (fallback).
 * Uses EIA2 (AES-CMAC) by default.
 *
 * @param ue_map     UE mapping with security keys
 * @param plain_nas  Plain 5G NAS message (without security header)
 * @param plain_len  Length of plain NAS
 * @param mac_out    Output buffer for 4-byte MAC
 * @return 0 on success, -1 on error
 */
int s1n2_compute_5g_uplink_mac(const ue_id_mapping_t *ue_map,
                               const uint8_t *plain_nas,
                               size_t plain_len,
                               uint8_t *mac_out);

/* Algorithm mapping tables (NEA↔EEA, NIA↔EIA) */
extern const uint8_t s1n2_nea_to_eea_map[8];
extern const uint8_t s1n2_nia_to_eia_map[8];

#ifdef __cplusplus
}
#endif

#endif /* S1N2_SECURITY_MODULE_H */
