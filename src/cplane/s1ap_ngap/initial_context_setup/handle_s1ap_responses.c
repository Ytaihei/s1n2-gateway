/**
 * @file handle_s1ap_responses.c
 * @brief ASN.1-decoded S1AP response/indication handler
 *
 * Handles InitialContextSetupResponse, InitialContextSetupFailure,
 * UEContextReleaseComplete, UEContextReleaseRequest,
 * ErrorIndication, and NASNonDeliveryIndication.
 * Falls through to unknown-message logging if no match.
 */
#include "internal/s1n2_converter_internal.h"
#include "error_handling/error_handling.h"
#include "s1ap_dispatch_handlers.h"

int s1ap_dispatch_asn1_responses(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    S1AP_S1AP_PDU_t *pdu_resp = NULL;
    asn_dec_rval_t dr_resp = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                                  (void **)&pdu_resp, data, len);
    if (dr_resp.code == RC_OK && pdu_resp) {
        if (pdu_resp->present == S1AP_S1AP_PDU_PR_successfulOutcome) {
            S1AP_SuccessfulOutcome_t *succ = pdu_resp->choice.successfulOutcome;
            if (succ && succ->procedureCode == S1AP_ProcedureCode_id_InitialContextSetup &&
                succ->value.present == S1AP_SuccessfulOutcome__value_PR_InitialContextSetupResponse) {
                printf("[DEBUG] Detected S1AP InitialContextSetupResponse (successfulOutcome)\n");
                fflush(stdout);

                /* Mark ICS completed for the corresponding UE mapping */
                ue_id_mapping_t *map = s1n2_context_find_recent_security(ctx);
                if (!map) {
                    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
                        if (ctx->ue_mappings[i].in_use) { map = &ctx->ue_mappings[i]; break; }
                    }
                }
                if (map) {
                    map->ics_completed = true;
                    map->ics_failed = false;
                    map->ics_sent = false;
                    map->ics_attempts += 1;
                    printf("[INFO] [ICS] Marked ICS completed (ENB=%ld, MME=%ld, attempts=%d)\n",
                           map->enb_ue_s1ap_id, map->mme_ue_s1ap_id, map->ics_attempts);
                }

                /* Extract E-RAB setup list and pre-register TEID mappings for GTP-U bridge */
                {
                    S1AP_InitialContextSetupResponse_t *s1ap_resp = &succ->value.choice.InitialContextSetupResponse;
                    for (int i = 0; i < s1ap_resp->protocolIEs.list.count; ++i) {
                        S1AP_InitialContextSetupResponseIEs_t *ie = s1ap_resp->protocolIEs.list.array[i];
                        if (!ie) continue;
                        if (ie->id == S1AP_ProtocolIE_ID_id_E_RABSetupListCtxtSURes &&
                            ie->value.present == S1AP_InitialContextSetupResponseIEs__value_PR_E_RABSetupListCtxtSURes) {
                            S1AP_E_RABSetupListCtxtSURes_t *erab_list = &ie->value.choice.E_RABSetupListCtxtSURes;
                            for (int j = 0; j < erab_list->list.count; ++j) {
                                S1AP_ProtocolIE_SingleContainer_8146P6_t *sc = (S1AP_ProtocolIE_SingleContainer_8146P6_t *)erab_list->list.array[j];
                                if (!sc || sc->value.present != S1AP_E_RABSetupItemCtxtSUResIEs__value_PR_E_RABSetupItemCtxtSURes)
                                    continue;

                                S1AP_E_RABSetupItemCtxtSURes_t *rab_item = &sc->value.choice.E_RABSetupItemCtxtSURes;

                                uint32_t s1u_ip_be = 0;
                                if (rab_item->transportLayerAddress.size >= 4 && rab_item->transportLayerAddress.buf) {
                                    memcpy(&s1u_ip_be, rab_item->transportLayerAddress.buf, 4);
                                }
                                uint32_t s1u_teid_be = 0;
                                if (rab_item->gTP_TEID.size >= 4 && rab_item->gTP_TEID.buf) {
                                    memcpy(&s1u_teid_be, rab_item->gTP_TEID.buf, 4);
                                }

                                uint32_t s1u_teid = ntohl(s1u_teid_be);
                                uint8_t pdu_session_id = (uint8_t)(rab_item->e_RAB_ID & 0xFF);

                                s1n2_uplane_register_ics_erab(ctx, map, s1u_teid, s1u_ip_be,
                                                              rab_item->e_RAB_ID, pdu_session_id);
                            }
                        }
                    }
                }

                /* Cache S1AP ICS Response data for deferred NGAP conversion */
                ue_id_mapping_t *map_for_queue = s1n2_context_find_recent_security(ctx);
                if (map_for_queue) {
                    size_t copy_len = (len <= sizeof(map_for_queue->pending_s1ap_ics)) ? len : sizeof(map_for_queue->pending_s1ap_ics);
                    memcpy(map_for_queue->pending_s1ap_ics, data, copy_len);
                    map_for_queue->pending_s1ap_ics_len = copy_len;
                    map_for_queue->has_pending_s1ap_ics = true;
                    printf("[INFO] [ICS] Cached S1AP InitialContextSetupResponse (%zu bytes), waiting for AMF ICS Request with QFI\n", copy_len);

                    if (map_for_queue->amf_ics_requested && map_for_queue->qfi > 0) {
                        printf("[INFO] [ICS] AMF ICS Request already received (QFI=%u); converting and sending NGAP ICS Response now\n", map_for_queue->qfi);
                        uint8_t ngap_data[512];
                        size_t ngap_len = sizeof(ngap_data);
                        if (s1n2_convert_initial_context_setup_response(map_for_queue->pending_s1ap_ics,
                                                                       map_for_queue->pending_s1ap_ics_len,
                                                                       ngap_data, &ngap_len, ctx) == 0) {
                            ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                                        NULL, 0, htonl(60), 0, 0, 0, 0);
                            if (sent == (ssize_t)ngap_len) {
                                printf("[INFO] InitialContextSetupResponse -> NGAP InitialContextSetupResponse sent (%zd bytes, PPID=60)\n", sent);
                                map_for_queue->has_pending_s1ap_ics = false;
                                map_for_queue->pending_s1ap_ics_len = 0;
                            } else {
                                printf("[WARN] Failed to send NGAP InitialContextSetupResponse via SCTP (ret=%zd, PPID=60, errno=%d: %s)\n",
                                       sent, errno, strerror(errno));
                            }
                        } else {
                            printf("[ERROR] Failed to convert cached S1AP ICS Response to NGAP\n");
                        }
                        fflush(stdout);
                    } else {
                        printf("[INFO] [ICS] Waiting for AMF InitialContextSetupRequest to extract QFI before NGAP conversion\n");
                    }
                } else {
                    /* Fallback: if no UE map, convert and send immediately (legacy behavior) */
                    uint8_t ngap_data[512];
                    size_t ngap_len = sizeof(ngap_data);
                    if (s1n2_convert_initial_context_setup_response(data, len, ngap_data, &ngap_len, ctx) == 0) {
                        ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                                    NULL, 0, htonl(60), 0, 0, 0, 0);
                        if (sent == (ssize_t)ngap_len) {
                            printf("[INFO] InitialContextSetupResponse -> NGAP InitialContextSetupResponse sent (%zd bytes, PPID=60)\n", sent);
                        } else {
                            printf("[WARN] Failed to send NGAP InitialContextSetupResponse via SCTP (ret=%zd, PPID=60, errno=%d: %s)\n",
                                   sent, errno, strerror(errno));
                        }
                    }
                    fflush(stdout);
                }
                ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                return 0;
            }
            /* UEContextReleaseComplete as successfulOutcome for procedure UEContextRelease */
            if (succ && succ->procedureCode == S1AP_ProcedureCode_id_UEContextRelease) {
                printf("[INFO] Detected S1AP UEContextReleaseComplete (successfulOutcome)\n");
                ue_id_mapping_t *map = s1n2_context_find_recent_security(ctx);
                if (map) {
                    map->ics_sent = false;
                    map->ics_completed = false;
                    map->ics_failed = false;
                    map->ics_e_rab_id = 0;
                    printf("[INFO] [ICS] Reset ICS state due to UEContextReleaseComplete (ENB=%ld)\n", map->enb_ue_s1ap_id);
                }
                fflush(stdout);
                ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                return 0;
            }
        } else if (pdu_resp->present == S1AP_S1AP_PDU_PR_unsuccessfulOutcome) {
            S1AP_UnsuccessfulOutcome_t *unsucc = pdu_resp->choice.unsuccessfulOutcome;
            if (unsucc && unsucc->procedureCode == S1AP_ProcedureCode_id_InitialContextSetup) {
                printf("[WARN] Detected S1AP InitialContextSetupFailure (unsuccessfulOutcome)\n");
                ue_id_mapping_t *map = s1n2_context_find_recent_security(ctx);
                if (map) {
                    map->ics_failed = true;
                    map->ics_sent = false;
                    map->ics_completed = false;
                    map->ics_attempts += 1;
                    printf("[INFO] [ICS] Marked ICS failed (ENB=%ld, MME=%ld, attempts=%d)\n",
                           map->enb_ue_s1ap_id, map->mme_ue_s1ap_id, map->ics_attempts);
                }
                fflush(stdout);
                ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                return 0;
            }
        } else if (pdu_resp->present == S1AP_S1AP_PDU_PR_initiatingMessage) {
            S1AP_InitiatingMessage_t *init = pdu_resp->choice.initiatingMessage;
            if (init) {
                switch (init->procedureCode) {
                    case S1AP_ProcedureCode_id_UEContextRelease:
                        if (init->value.present == S1AP_InitiatingMessage__value_PR_UEContextReleaseRequest) {
                            s1n2_handle_s1ap_ue_context_release(ctx,
                                &init->value.choice.UEContextReleaseRequest);
                            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                            return 0;
                        }
                        break;
                    case S1AP_ProcedureCode_id_ErrorIndication:
                        if (init->value.present == S1AP_InitiatingMessage__value_PR_ErrorIndication) {
                            s1n2_handle_s1ap_error_indication(ctx,
                                &init->value.choice.ErrorIndication);
                            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                            return 0;
                        }
                        break;
                    case S1AP_ProcedureCode_id_NASNonDeliveryIndication:
                        if (init->value.present == S1AP_InitiatingMessage__value_PR_NASNonDeliveryIndication) {
                            s1n2_handle_s1ap_nas_non_delivery(ctx,
                                &init->value.choice.NASNonDeliveryIndication);
                            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);
                            return 0;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
    if (pdu_resp) ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu_resp);

    /* Unknown S1AP message — log and discard */
    printf("[WARN] Unknown S1AP message type: %02x %02x (procedure code %d, len=%zd)\n",
           data[0], data[1], data[1], len);
    printf("[HEX] Unknown S1AP message (%zd bytes): ", len);
    for (size_t i = 0; i < len && i < 64; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    fflush(stdout);
    return 0;
}
