#include "s1n2_log.h"
/**
 * @file dispatcher_s1ap.c
 * @brief S1AP message dispatcher — thin router
 *
 * Routes incoming S1AP messages to message-type-specific handlers.
 * Each handler lives in its own translation unit for SRP compliance.
 *
 * Handlers:
 *   handle_s1_setup.c              — S1SetupRequest (proc 17)
 *   handle_initial_ue.c            — InitialUEMessage (proc 0x0C)
 *   handle_nas_transport_dispatch.c — NAS Transport UL/DL (proc 0x0D)
 *   handle_s1ap_responses.c        — ICS Response/Failure, UEContextRelease, etc.
 */
#include "internal/s1n2_converter_internal.h"
#include "s1ap_dispatch_handlers.h"

int s1n2_handle_s1c_message(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    if (len < 4) {
        LOG_DEBUG("S1C message too short (%zd bytes)\n", len);

        return -1;
    }

    LOG_DEBUG("S1C received %zd bytes\n", len);

    /* Full message hexdump for debugging */

    /* Route to message-type-specific handler */
    if (data[0] == 0x00 && data[1] == 0x11)
        return s1ap_dispatch_s1_setup(ctx, data, len);

    if (data[0] == 0x00 && data[1] == 0x0C)
        return s1ap_dispatch_initial_ue(ctx, data, len);

    if (data[0] == 0x00 && data[1] == 0x0D)
        return s1ap_dispatch_nas_transport(ctx, data, len);

    return s1ap_dispatch_asn1_responses(ctx, data, len);
}
