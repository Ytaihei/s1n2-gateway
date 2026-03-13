/**
 * @file s1ap_dispatch_handlers.h
 * @brief S1AP dispatch handler declarations
 *
 * Forward declarations for message-type-specific S1AP handlers
 * called from the thin dispatcher in dispatcher_s1ap.c.
 */
#ifndef S1AP_DISPATCH_HANDLERS_H
#define S1AP_DISPATCH_HANDLERS_H

#include "internal/s1n2_converter_internal.h"

/**
 * Handle S1SetupRequest (procedure code 17).
 * Resets ICS state, converts to NGSetupRequest, queues or sends to AMF.
 */
int s1ap_dispatch_s1_setup(s1n2_context_t *ctx, uint8_t *data, size_t len);

/**
 * Handle InitialUEMessage (procedure code 0x0C).
 * ASN.1 decode, UE mapping, NAS extraction, 4G→5G NAS conversion,
 * NGAP InitialUEMessage build and SCTP send.
 */
int s1ap_dispatch_initial_ue(s1n2_context_t *ctx, uint8_t *data, size_t len);

/**
 * Handle NAS Transport (procedure code 0x0D).
 * Direction classification (UL/DL), conversion, SCTP send,
 * PDU Session Establishment trigger.
 */
int s1ap_dispatch_nas_transport(s1n2_context_t *ctx, uint8_t *data, size_t len);

/**
 * Handle remaining S1AP messages via ASN.1 decode.
 * InitialContextSetupResponse/Failure, UEContextRelease,
 * ErrorIndication, NASNonDeliveryIndication, and unknown fallback.
 */
int s1ap_dispatch_asn1_responses(s1n2_context_t *ctx, uint8_t *data, size_t len);

#endif /* S1AP_DISPATCH_HANDLERS_H */
