/**
 * @file pdu_session/pdu_session.h
 * @brief PDU Session module public API
 *
 * Provides PDU session management functions:
 *   - Active context detection and session mapping search
 *   - PDU session status mask encoding
 *   - PDU Session Establishment Request builder
 *   - UL NAS Transport with N1 SM information wrapper
 *
 * Created during Phase 4 NAS modularization.
 *
 * @see 3GPP TS 24.501 § 8.3 (5GS session management)
 * @see 3GPP TS 24.501 § 8.2.7 (UL NAS Transport)
 */
#ifndef S1N2_PDU_SESSION_H
#define S1N2_PDU_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations to avoid circular includes */
typedef struct s1n2_context s1n2_context_t;
typedef struct ue_id_mapping ue_id_mapping_t;

/* ================================================================
 * PDU Session helper functions
 * ================================================================ */

/**
 * @brief Check if a UE mapping has an active PDU context
 *
 * Checks ICS completion, UPF N3 info, eNB S1-U info, uplink TEID,
 * and TEID preservation flags.
 *
 * @param map UE mapping to check
 * @return true if active PDU context exists
 */
bool s1n2_has_active_pdu_context(const ue_id_mapping_t *map);

/**
 * @brief Infer active PDU session ID from UE mapping
 *
 * Returns cached PSI if valid (1-15), otherwise defaults to 5.
 *
 * @param map UE mapping
 * @return PDU session ID (1-15)
 */
uint8_t s1n2_infer_active_pdu_session_id(const ue_id_mapping_t *map);

/**
 * @brief Find UE mapping with active PDU session
 *
 * Searches by IMSI/GUTI across all UE contexts if current has no active session.
 * WARNING: Searches all UE contexts — assumes single-threaded access.
 *
 * @param ctx  S1N2 context with UE mappings
 * @param current  Current UE mapping (may lack active session)
 * @return UE mapping with active PDU session, or NULL
 */
ue_id_mapping_t *s1n2_find_session_mapping(s1n2_context_t *ctx,
                                           ue_id_mapping_t *current);

/**
 * @brief Build PDU session status bitmask
 *
 * Constructs a 16-bit bitmask with the active PSI bit set.
 * Also copies cached GUTI and access type from source mapping if needed.
 *
 * @param ctx     S1N2 context
 * @param ue_map  Current UE mapping
 * @return 16-bit PDU session status mask (0 if no active session)
 */
uint16_t s1n2_build_pdu_session_status_mask(s1n2_context_t *ctx,
                                            ue_id_mapping_t *ue_map);

/**
 * @brief Append PDU Session Status IE to NAS buffer
 *
 * Encodes IEI 0x50, length 2, and the status mask bytes.
 *
 * @param nas         NAS buffer
 * @param offset      Current write offset (updated on return)
 * @param capacity    Buffer capacity
 * @param status_mask 16-bit PDU session status mask
 * @return 0 on success, -1 on error
 */
int s1n2_append_pdu_session_status(uint8_t *nas, size_t *offset,
                                   size_t capacity, uint16_t status_mask);

/* ================================================================
 * PDU Session message builders
 * ================================================================ */

/**
 * @brief Build 5G PDU Session Establishment Request
 *
 * Constructs a 5GSM PDU Session Establishment Request with optional
 * integrity protection using K_NASint_5G.
 *
 * @param nas_5g          Output buffer
 * @param nas_5g_len      Input: buffer size, Output: actual length
 * @param ue_map          UE context for security (optional, can be NULL)
 * @param pdu_session_id  PDU Session ID (1-15)
 * @param dnn             Data Network Name (e.g., "internet")
 * @param sst             Slice Service Type (typically 1)
 * @return 0 on success, -1 on error
 *
 * @see 3GPP TS 24.501 § 8.3.1
 */
int build_pdu_session_establishment_request(uint8_t *nas_5g,
                                            size_t *nas_5g_len,
                                            ue_id_mapping_t *ue_map,
                                            uint8_t pdu_session_id,
                                            const char *dnn,
                                            uint8_t sst);

/**
 * @brief Build 5GMM UL NAS Transport with N1 SM information
 *
 * Wraps a PDU Session Establishment Request inside a UL NAS Transport
 * message with integrity protection.
 *
 * @param nas_5g          Output buffer
 * @param nas_5g_len      Input: buffer size, Output: actual length
 * @param ue_map          UE context with security keys
 * @param pdu_session_id  PDU Session ID (1-15)
 * @param dnn             Data Network Name
 * @param sst             Slice Service Type
 * @param request_type    Request type (1=initial, 2=existing, 3=modification)
 * @return 0 on success, -1 on error
 *
 * @see 3GPP TS 24.501 § 8.2.7
 */
int build_gmm_ul_nas_transport_with_n1_sm(uint8_t *nas_5g,
                                           size_t *nas_5g_len,
                                           ue_id_mapping_t *ue_map,
                                           uint8_t pdu_session_id,
                                           const char *dnn,
                                           uint8_t sst,
                                           uint8_t request_type);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_PDU_SESSION_H */
