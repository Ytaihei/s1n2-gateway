#include "s1n2_log.h"
/**
 * @file handle_s1_setup.c
 * @brief S1SetupRequest handler (procedure code 17)
 *
 * Resets ICS state for all UE mappings (eNB restart assumed),
 * converts S1SetupRequest to NGSetupRequest, and queues or sends to AMF.
 */
#include "internal/s1n2_converter_internal.h"
#include "s1_setup/s1_setup.h"
#include "s1ap_dispatch_handlers.h"

int s1ap_dispatch_s1_setup(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    LOG_DEBUG("S1SetupRequest detected\n");

    /* Proactive: eNB likely restarted. Reset ICS state for all UE mappings. */
    if (ctx) {
        size_t cleared = 0;
        for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
            if (ctx->ue_mappings[i].in_use) {
                ctx->ue_mappings[i].ics_sent = false;
                ctx->ue_mappings[i].ics_completed = false;
                ctx->ue_mappings[i].ics_failed = false;
                ctx->ue_mappings[i].ics_e_rab_id = 0;
                cleared++;
            }
        }
        if (cleared)
            LOG_INFO("[ICS] Reset ICS state for %zu UE mapping(s) due to new S1SetupRequest (eNB restart)\n", cleared);
    }

    /* Convert S1AP S1SetupRequest to NGAP NGSetupRequest */
    uint8_t ngap_data[1024];
    size_t ngap_len = sizeof(ngap_data);

    LOG_DEBUG("Calling s1n2_convert_s1setup_to_ngsetup\n");

    int result = s1n2_convert_s1setup_to_ngsetup(data, len, ngap_data, &ngap_len);
    LOG_DEBUG("s1n2_convert_s1setup_to_ngsetup result: %d\n", result);

    if (result == 0) {
        /* Check N2 connection before sending */
        if (!ctx->n2_connected) {
            /* Store S1SetupRequest for later processing when N2 connects */
            if (len <= sizeof(ctx->pending_s1setup.s1ap_data)) {
                memcpy(ctx->pending_s1setup.s1ap_data, data, len);
                ctx->pending_s1setup.s1ap_len = len;
                ctx->pending_s1setup.received_time = time(NULL);
                ctx->has_pending_s1setup = true;
                LOG_INFO("N2 connection not established, S1SetupRequest queued for later processing\n");
            } else {
                LOG_ERROR("S1SetupRequest too large to queue (%zu bytes)\n", len);
            }

            return 0;
        }

        /* Send NGAP NGSetupRequest to AMF with SCTP PPID=60 (NGAP) */
        ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                    NULL, 0, htonl(60), 0, 0, 0, 0);
        if (sent == (ssize_t)ngap_len) {
            LOG_INFO("S1SetupRequest -> NGSetupRequest sent (%zd bytes, PPID=60)\n", sent);

        } else {
            LOG_ERROR("Failed to send NGSetupRequest via SCTP (ret=%zd, PPID=60, errno=%d)\n", sent, errno);

        }
    }
    return 0;
}
