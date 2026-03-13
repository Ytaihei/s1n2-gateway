#ifndef S1N2_ICS_H
#define S1N2_ICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration (matches s1n2_converter.h typedef)
typedef struct s1n2_context s1n2_context_t;

/**
 * Enqueue pending S1AP InitialContextSetupResponse for deferred NGAP conversion
 * @param ctx S1N2 context
 * @param s1ap_data Raw S1AP ICS Response message data
 * @param s1ap_len Length of S1AP message
 * @return 0 on success, -1 on error
 */
int ics_state_enqueue_pending_s1ap_ics(s1n2_context_t *ctx,
                                       const uint8_t *s1ap_data,
                                       size_t s1ap_len);

/**
 * Dequeue and convert pending S1AP ICS Response to NGAP (with QFI from AMF request)
 * @param ctx S1N2 context
 * @param ngap_data Output buffer for NGAP ICS Response
 * @param ngap_len Pointer to buffer length (in/out)
 * @return 0 on success, -1 on error (no pending ICS, conversion failed, etc.)
 */
int ics_state_dequeue_pending_s1ap_ics(s1n2_context_t *ctx,
                                       uint8_t *ngap_data,
                                       size_t *ngap_len);

/**
 * Mark that AMF has sent InitialContextSetupRequest (enables deferred ICS processing)
 * @param ctx S1N2 context
 * @return 0 on success, -1 on error
 */
int ics_state_mark_amf_ics_requested(s1n2_context_t *ctx);

/**
 * Check if pending S1AP ICS Response is cached
 * @param ctx S1N2 context
 * @return true if pending ICS exists, false otherwise
 */
bool ics_state_has_pending_s1ap_ics(s1n2_context_t *ctx);

/**
 * Convert NGAP InitialContextSetupRequest to S1AP (wrapper for existing function)
 * @param ngap_data NGAP ICS Request message
 * @param ngap_len Length of NGAP message
 * @param s1ap_data Output buffer for S1AP ICS Request
 * @param s1ap_len Pointer to buffer length (in/out)
 * @param ctx S1N2 context
 * @return 0 on success, -1 on error
 */
int ics_request_convert_ngap_to_s1ap(const uint8_t *ngap_data, size_t ngap_len,
                                     uint8_t *s1ap_data, size_t *s1ap_len,
                                     s1n2_context_t *ctx);

/**
 * Handle NGAP InitialContextSetupRequest from AMF
 * Parses ICS IEs, extracts UPF N3 tunnel/QFI, processes pending ICS,
 * and builds/sends S1AP InitialContextSetupRequest to eNB.
 * @param ctx S1N2 context
 * @param init_msg Decoded NGAP InitiatingMessage (void* to avoid header dependency)
 * @return 0 if handled, -1 if not handled
 */
int ics_request_handle_ngap_ics(s1n2_context_t *ctx, void *init_msg);

#ifdef __cplusplus
}
#endif

#endif // S1N2_ICS_H
