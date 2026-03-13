/**
 * @file tau/tau.h
 * @brief Public API for TAU (Tracking Area Update) module
 *
 * Phase 6 of NAS modularization.
 * Provides TAU Request 4G→5G conversion and TAU Accept builder.
 *
 * TAU helpers (type mapping, update IE appending) are in tau/tau_helpers.c
 * and declared in internal/nas_module_common.h (Phase 1 extraction).
 */
#ifndef S1N2_NAS_TAU_H
#define S1N2_NAS_TAU_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Forward declarations */
typedef struct s1n2_context s1n2_context_t;
typedef struct ue_id_mapping ue_id_mapping_t;

/**
 * @brief Convert 4G TAU Request (0x48) → 5G Registration Request (mobility update)
 *
 * Uses cached 5G-GUTI for mobile identity, appends update_type and
 * last_visited_tai IEs.  Applies integrity protection if security
 * context is available.
 *
 * Split from registration/attach_request_4g_to_5g.c during Phase 6.
 *
 * @param nas_4g     Raw 4G NAS PDU (after security header strip)
 * @param nas_4g_len Length of 4G NAS PDU
 * @param first_byte First byte of 4G NAS (contains PD)
 * @param payload_offset Offset to first IE after message type
 * @param nas_5g     Output buffer for 5G NAS PDU
 * @param nas_5g_len [in] buffer capacity, [out] written length
 * @param ctx        Converter context (for PDU session search)
 * @param ue_map     UE-level context (security keys, cached GUTI, etc.)
 * @return 0 on success, -1 on error
 */
int tau_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
                                 uint8_t first_byte, size_t payload_offset,
                                 uint8_t *nas_5g, size_t *nas_5g_len,
                                 s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/**
 * @brief Build 4G TAU Accept NAS message from scratch
 *
 * Constructs a complete EPS Tracking Area Update Accept message with:
 *   - EPS Update Result derived from EPS Update Type
 *   - T3412 timer (default 9 minutes)
 *   - TAI list (from cached location or environment)
 *   - LAI (for combined TA/LA updates)
 *   - EPS bearer context status
 *   - NAS security wrapping (cipher + integrity or integrity-only)
 *
 * Moved from nas_builders.c during Phase 6.
 *
 * @param ctx                 Converter context (unused, reserved)
 * @param ue_map              UE-level context (security keys, location, etc.)
 * @param eps_update_type_octet Raw EPS update type octet from TAU Request
 * @param out                 Output buffer for wrapped NAS message
 * @param out_len             [in] buffer capacity, [out] written length
 * @return 0 on success, -1 on error
 */
int s1n2_build_tau_accept_nas(s1n2_context_t *ctx,
                              ue_id_mapping_t *ue_map,
                              uint8_t eps_update_type_octet,
                              uint8_t *out,
                              size_t *out_len);

#endif /* S1N2_NAS_TAU_H */
