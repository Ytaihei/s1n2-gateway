/**
 * @file error_handling.h
 * @brief S1AP→NGAP error/release message handler declarations
 *
 * Provides handler functions for:
 *   - UEContextReleaseRequest (S1AP→NGAP bridge)
 *   - ErrorIndication          (S1AP→NGAP bridge)
 *   - NASNonDeliveryIndication (S1AP→NGAP bridge)
 *
 * Each handler extracts IEs from the decoded S1AP message, maps UE IDs,
 * translates the S1AP cause to NGAP, builds the corresponding NGAP PDU,
 * and forwards it via SCTP on the N2 interface.
 */
#ifndef S1N2_ERROR_HANDLING_H
#define S1N2_ERROR_HANDLING_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration (matches s1n2_converter.h typedef) */
typedef struct s1n2_context s1n2_context_t;

/**
 * Handle S1AP UEContextReleaseRequest → NGAP UEContextReleaseRequest
 *
 * Extracts eNB/MME UE IDs, maps to RAN/AMF IDs, converts S1AP cause
 * to NGAP cause, builds NGAP UEContextReleaseRequest and forwards it.
 * Also resets ICS state for the affected UE mapping.
 *
 * @param ctx   S1N2 context (for ID mapping and N2 socket)
 * @param msg   Decoded S1AP_UEContextReleaseRequest_t* (passed as void*)
 * @return 0 on success, -1 on error
 */
int s1n2_handle_s1ap_ue_context_release(s1n2_context_t *ctx, void *msg);

/**
 * Handle S1AP ErrorIndication → NGAP ErrorIndication
 *
 * Extracts eNB/MME UE IDs and cause, maps to RAN/AMF IDs, converts
 * S1AP cause to NGAP cause, builds NGAP ErrorIndication and forwards it.
 *
 * @param ctx   S1N2 context (for ID mapping and N2 socket)
 * @param msg   Decoded S1AP_ErrorIndication_t* (passed as void*)
 * @return 0 on success, -1 on error
 */
int s1n2_handle_s1ap_error_indication(s1n2_context_t *ctx, void *msg);

/**
 * Handle S1AP NASNonDeliveryIndication → NGAP NASNonDeliveryIndication
 *
 * Extracts eNB/MME UE IDs, NAS PDU, and cause from S1AP message,
 * maps to RAN/AMF IDs, converts S1AP cause to NGAP cause,
 * builds NGAP NASNonDeliveryIndication and forwards it.
 *
 * @param ctx   S1N2 context (for ID mapping and N2 socket)
 * @param msg   Decoded S1AP_NASNonDeliveryIndication_t* (passed as void*)
 * @return 0 on success, -1 on error
 */
int s1n2_handle_s1ap_nas_non_delivery(s1n2_context_t *ctx, void *msg);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_ERROR_HANDLING_H */
