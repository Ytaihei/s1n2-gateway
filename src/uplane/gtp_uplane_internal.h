/**
 * @file gtp_uplane_internal.h
 * @brief Internal API declarations for GTP-U sub-modules
 *
 * Used only within src/uplane/ — not part of the public API.
 */
#ifndef GTP_UPLANE_INTERNAL_H
#define GTP_UPLANE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include "s1n2_converter.h"

/**
 * Handle GTP-U Echo Request / Echo Response.
 *
 * @param ctx     Converter context (uses n3_fd for sending responses)
 * @param teid    TEID from the received GTP-U header
 * @param msg_type  GTP-U message type (1=Echo Request, 2=Echo Response)
 * @return 0 on success, -1 on failure
 */
int s1n2_handle_gtpu_echo(s1n2_context_t *ctx, uint32_t teid, uint8_t msg_type);

/**
 * Forward an uplink G-PDU (eNB → UPF): S1-U → N3 with TEID translation.
 *
 * @param ctx      Converter context
 * @param data     Raw GTP-U packet
 * @param len      Packet length
 * @param teid     Original TEID from the GTP-U header
 * @param ue_map   UE mapping entry (may be NULL for legacy path)
 * @return 0 on success, -1 on failure
 */
int s1n2_forward_uplink(s1n2_context_t *ctx, uint8_t *data, size_t len,
                        uint32_t teid, ue_id_mapping_t *ue_map);

/**
 * Forward a downlink G-PDU (UPF → eNB): N3 → S1-U (transparent proxy).
 *
 * @param ctx      Converter context
 * @param data     Raw GTP-U packet
 * @param len      Packet length
 * @param teid     Original TEID from the GTP-U header
 * @param ue_map   UE mapping entry with eNB S1-U info
 * @return 0 on success, -1 on failure
 */
int s1n2_forward_downlink(s1n2_context_t *ctx, uint8_t *data, size_t len,
                          uint32_t teid, ue_id_mapping_t *ue_map);

/**
 * Legacy fallback for unknown TEIDs: try both directions.
 *
 * @param ctx      Converter context
 * @param data     Raw GTP-U packet
 * @param len      Packet length
 * @param teid     Unknown TEID from the GTP-U header
 * @return 0 on success, -1 on failure
 */
int s1n2_forward_legacy(s1n2_context_t *ctx, uint8_t *data, size_t len,
                        uint32_t teid);

#endif /* GTP_UPLANE_INTERNAL_H */
