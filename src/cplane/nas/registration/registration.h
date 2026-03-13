/**
 * @file registration/registration.h
 * @brief Registration / Attach module — public API
 *
 * Phase 5 of NAS modularization.
 * Provides converters for:
 *   - Attach Complete  (4G 0x43 → 5G Registration Complete 0x43)
 *   - Attach Request   (4G 0x41/0x0C → 5G Registration Request 0x41)
 *   - Registration Accept  (5G 0x42 → 4G Attach Accept 0x42)
 *   - Registration Reject  (5G 0x44 → 4G Attach Reject 0x44)
 * Also provides identity helper functions.
 *
 * NOTE: Attach Request and TAU Request (0x48) share the same builder code
 * path in attach_request_4g_to_5g.c. TAU will be split into tau/ in Phase 6.
 */
#ifndef S1N2_REGISTRATION_H
#define S1N2_REGISTRATION_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct s1n2_context;
typedef struct s1n2_context s1n2_context_t;
struct ue_id_mapping;
typedef struct ue_id_mapping ue_id_mapping_t;

/* ---- Converters ---- */

/**
 * Convert 4G Attach Complete (0x43) → 5G Registration Complete (0x43)
 * Builds plain or integrity-protected 5G NAS. Sets PDU session establishment flag.
 */
int attach_complete_convert_4g_to_5g(uint8_t *nas_5g, size_t *nas_5g_len,
                                     ue_id_mapping_t *ue_map);

/**
 * Convert 4G Attach Request (0x41/0x0C) or TAU Request (0x48) → 5G Registration Request (0x41)
 *
 * Handles both initial registration (SUCI) and mobility update (cached 5G-GUTI).
 * TAU-specific IEs (update_type, last_visited_tai) are appended when msg_type == 0x48.
 * ESM PDN request is cached for Attach Request only.
 *
 * NOTE: TAU Request handling will be split to tau/tau_request_4g_to_5g.c in Phase 6.
 */
int attach_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                    uint8_t first_byte, uint8_t msg_type,
                                    size_t payload_offset,
                                    uint8_t *nas_5g, size_t *nas_5g_len,
                                    s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/**
 * Convert 5G Registration Accept (0x42) → 4G Attach Accept (0x42)
 * Builds complete Attach Accept with ESM container, NAS security wrapping.
 * Caches 5G-GUTI and registration artifacts.
 */
int registration_accept_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                         uint8_t *nas_4g, size_t *nas_4g_len,
                                         ue_id_mapping_t *security_cache);

/**
 * Convert 5G Registration Reject (0x44) → 4G Attach Reject (0x44)
 * Simple cause code mapping.
 */
int registration_reject_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
                                         uint8_t *nas_4g, size_t *nas_4g_len);

/* ---- Identity helpers ---- */

/**
 * Locate EPS Mobile Identity IE in 4G NAS PDU.
 * Scans for BCD-encoded identity starting from start_offset.
 * @return offset of the length byte, or -1 if not found
 */
int s1n2_locate_eps_mobile_identity(const uint8_t *nas, size_t nas_len,
                                    size_t start_offset,
                                    const uint8_t **value_ptr,
                                    size_t *value_len);

/**
 * Get fallback IMSI from environment variables.
 * Checks S1N2_FALLBACK_IMSI, UE1_IMSI, UE_IMSI, IMSI in order.
 * @return pointer to environment string, or NULL
 */
const char *s1n2_get_fallback_imsi(void);

/**
 * Extract IMSI from 5G Registration Request (SUCI).
 * Decodes MCC/MNC from PLMN and BCD digits from MSIN.
 */
int s1n2_extract_imsi_from_5g_registration_request(const uint8_t *nas_pdu,
                                                   size_t nas_len,
                                                   char *imsi_out,
                                                   size_t imsi_len);

/**
 * Scan 4G NAS PDU for UE Security Capability IE (IEI 0x5E) and cache
 * it in the UE mapping for cross-module use (e.g. SMC builder).
 *
 * @param ue_map          UE mapping to update (may be NULL — no-op)
 * @param nas_4g          Input 4G NAS PDU
 * @param nas_4g_len      Length of NAS PDU
 * @param payload_offset  Start offset for IE scanning
 */
void cache_ue_security_capability(ue_id_mapping_t *ue_map,
                                  const uint8_t *nas_4g, size_t nas_4g_len,
                                  size_t payload_offset);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_REGISTRATION_H */
