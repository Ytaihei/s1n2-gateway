#include "s1n2_log.h"
/**
 * @file dispatcher_ngap.c
 * @brief NGAP message dispatcher
 *
 * Routes incoming NGAP messages to appropriate conversion handlers.
 * Relocated from src/cplane/ngap_dispatcher.c during final refactoring.
 */
#include "internal/s1n2_converter_internal.h"
#include "s1_setup/s1_setup.h"
#include "ngap_setup/ngap_setup.h"
#include "initial_context_setup/ics.h"
#include "initial_ue_message/initial_ue.h"
#include "nas_transport/nas_transport.h"
#include "transport/sctp_transport.h"

int s1n2_handle_n2_message(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    if (len < 4) {
        return -1; // Too short
    }

    // Debug dump of inbound N2/NGAP message
    LOG_DEBUG("N2 received %zu bytes\n", len);

    int handled = 0;
    NGAP_NGAP_PDU_t *ngpdu = NULL;
    asn_dec_rval_t ndr = aper_decode_complete(NULL, &asn_DEF_NGAP_NGAP_PDU, (void**)&ngpdu, data, len);
    if (ndr.code != RC_OK || !ngpdu) {
        const char *rc = (ndr.code==RC_OK)?"RC_OK":(ndr.code==RC_FAIL?"RC_FAIL":(ndr.code==RC_WMORE?"RC_WMORE":"RC_UNKNOWN"));
        LOG_WARN("NGAP decode failed or incomplete: result=%s consumed=%zu\n", rc, (size_t)ndr.consumed);

        goto cleanup;
    }

    if (ngpdu->present == NGAP_NGAP_PDU_PR_successfulOutcome) {
        NGAP_SuccessfulOutcome_t *succ = ngpdu->choice.successfulOutcome;
        if (succ && succ->value.present == NGAP_SuccessfulOutcome__value_PR_NGSetupResponse) {
            NGAP_NGSetupResponse_t *rsp = &succ->value.choice.NGSetupResponse;
            int ie_count = rsp->protocolIEs.list.count;
            LOG_INFO("NGSetupResponse decoded: IE count=%d\n", ie_count);
            for (int i = 0; i < ie_count && i < 8; ++i) {
                NGAP_NGSetupResponseIEs_t *ie = rsp->protocolIEs.list.array[i];
                if (!ie) continue;
                LOG_INFO("NGSetupResponse IE[%d]: id=%ld\n", i, (long)ie->id);
            }

            uint8_t s1ap_data[1024];
            size_t s1ap_len = sizeof(s1ap_data);

            if (s1n2_convert_ngsetup_to_s1setup(data, len, s1ap_data, &s1ap_len) == 0) {
                if (ctx->s1c_fd <= 0) {
                    LOG_WARN("S1C connection closed, cannot send S1SetupResponse\n");

                    goto cleanup;
                }

                ssize_t sent = sctp_retry_send(ctx->s1c_fd, s1ap_data, s1ap_len, 18, 1500,
                                               "NGSetupResponse -> S1SetupResponse");
                if (sent > 0) {
                    handled = 1;
                }
                goto cleanup;
            }
        }
    } else if (ngpdu->present == NGAP_NGAP_PDU_PR_initiatingMessage) {
        NGAP_InitiatingMessage_t *init = ngpdu->choice.initiatingMessage;
        if (init && init->procedureCode == NGAP_ProcedureCode_id_DownlinkNASTransport &&
            init->value.present == NGAP_InitiatingMessage__value_PR_DownlinkNASTransport) {
            LOG_DEBUG("NGAP DownlinkNASTransport detected (proc=0x%lX)\n", (long)init->procedureCode);

            uint8_t s1ap_data[1024];
            size_t s1ap_len = sizeof(s1ap_data);

            if (s1n2_convert_ngap_downlink_nas_transport(ctx, data, len, s1ap_data, &s1ap_len) == 0) {
                if (s1ap_len == 0) { handled = 1; goto cleanup; }
                if (ctx->s1c_fd <= 0) {
                    LOG_WARN("S1C connection closed, cannot forward DownlinkNASTransport\n");

                    goto cleanup;
                }

                ssize_t sent = sctp_retry_send(ctx->s1c_fd, s1ap_data, s1ap_len, 18, 1500,
                                               "NGAP DownlinkNASTransport -> S1AP");
                if (sent > 0) {
                    handled = 1;
                }
            }
     } else if (init && init->procedureCode == NGAP_ProcedureCode_id_InitialContextSetup &&
             init->value.present == NGAP_InitiatingMessage__value_PR_InitialContextSetupRequest) {
         // Delegate to extracted ICS Request handler module
            int ics_ret = ics_request_handle_ngap_ics(ctx, init);
            if (ics_ret == 0) {
                handled = 1;
            }
        }
    }

cleanup:
    if (ngpdu) ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, ngpdu);
    return handled ? 0 : -1;
}
