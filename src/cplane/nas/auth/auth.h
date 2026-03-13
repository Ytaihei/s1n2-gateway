/**
 * @file auth/auth.h
 * @brief Public API for Authentication module
 *
 * Provides functions for converting 4G/5G Authentication messages:
 *   - Auth Request (5G→4G): 5G Authentication Request → 4G Authentication Request
 *   - Auth Response (4G→5G): 4G Authentication Response → 5G Authentication Response (RES*)
 *   - Auth Failure (4G→5G): 4G Authentication Failure (AUTS) → 5G Authentication Failure
 *
 * Created during Phase 2 NAS modularization.
 *
 * @see 3GPP TS 24.301 (NAS for EPS)
 * @see 3GPP TS 24.501 (NAS for 5GS)
 * @see 3GPP TS 33.401 / TS 33.501 (Security)
 */
#ifndef S1N2_AUTH_H
#define S1N2_AUTH_H

#include <stddef.h>
#include <stdint.h>

/* Forward declarations — avoid pulling heavyweight headers into auth.h */
typedef struct s1n2_context   s1n2_context_t;
typedef struct ue_id_mapping  ue_id_mapping_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Convert 5G Authentication Request (0x56) to 4G Authentication Request (0x52)
 *
 * Extracts RAND (16 bytes) and AUTN (16 bytes) from the 5G message and
 * builds a 4G EMM Authentication Request.
 *
 * @param msg        Inner 5G NAS message (after security header stripping)
 * @param msg_len    Length of inner message
 * @param nas_4g     Output buffer for 4G NAS
 * @param nas_4g_len In: capacity, Out: actual length
 * @return 0 on success, -1 on error
 */
int auth_request_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                  uint8_t *nas_4g, size_t *nas_4g_len);

/**
 * @brief Convert 4G Authentication Response (0x53) to 5G Authentication Response (0x57)
 *
 * Parses 4G RES, computes 5G RES* using subscriber keys, and derives
 * both 4G (KASME, K_NASint/enc) and 5G (Kausf→Kseaf→Kamf→K_NASint/enc_5G) keys.
 *
 * @warning This function modifies ue_map security context (key derivation).
 *          Key derivation order must be preserved for security correctness.
 *
 * @param nas_4g         Input 4G NAS message
 * @param nas_4g_len     Length of input
 * @param payload_offset Offset to message payload (after PD+msg_type)
 * @param nas_5g         Output buffer for 5G NAS
 * @param nas_5g_len     In: capacity, Out: actual length
 * @param ctx            Converter context (for auth key lookup)
 * @param ue_map         UE mapping with cached RAND/AUTN/IMSI
 * @return 0 on success, -1 on error
 */
int auth_response_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                   size_t payload_offset,
                                   uint8_t *nas_5g, size_t *nas_5g_len,
                                   s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/**
 * @brief Convert 4G Authentication Failure (0x5C) to 5G Authentication Failure (0x59)
 *
 * Parses EMM cause and AUTS (SQN resynchronization), builds 5G Authentication
 * Failure with AUTS IE. Optionally decodes UE's expected SQN for diagnostics.
 *
 * @param nas_4g         Input 4G NAS message
 * @param nas_4g_len     Length of input
 * @param payload_offset Offset to message payload (after PD+msg_type)
 * @param nas_5g         Output buffer for 5G NAS
 * @param nas_5g_len     In: capacity, Out: actual length
 * @param ctx            Converter context (for auth key lookup, SQN decoding)
 * @param ue_map         UE mapping (for cached RAND, IMSI)
 * @return 0 on success, -1 on error
 */
int auth_failure_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                  size_t payload_offset,
                                  uint8_t *nas_5g, size_t *nas_5g_len,
                                  s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_AUTH_H */
