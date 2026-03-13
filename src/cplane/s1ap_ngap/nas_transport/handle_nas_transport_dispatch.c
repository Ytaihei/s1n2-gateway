/**
 * @file handle_nas_transport_dispatch.c
 * @brief NAS Transport dispatcher (procedure code 0x0D)
 *
 * Classifies NAS Transport direction (Uplink/Downlink) via ASN.1 decode
 * or heuristic fallback, then converts and forwards to AMF.
 * Triggers PDU Session Establishment after Registration Complete.
 */
#include "internal/s1n2_converter_internal.h"
#include "nas_transport/nas_transport.h"
#include "s1ap_dispatch_handlers.h"

/* Feature toggle: Use 5GMM UL NAS Transport wrapper for PDU Session Establishment Request */
static const int USE_UL_NAS_TRANSPORT_WRAPPER = 1;

int s1ap_dispatch_nas_transport(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    printf("[DEBUG] [PROC=0x0D] Received S1AP NAS Transport (len=%zu, head=%02X %02X %02X %02X)\n",
           len, data[0], data[1], (len>2?data[2]:0), (len>3?data[3]:0));
    bool is_uplink = false;
    bool classified = false;
    uint8_t classified_nas_pd = 0x00;
    uint8_t classified_nas_type = 0x00;
    bool nas_signature_known = false;

    S1AP_S1AP_PDU_t *nas_transport_pdu = NULL;
    asn_dec_rval_t nas_transport_dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                                           (void **)&nas_transport_pdu,
                                                           data, len);
    if (nas_transport_dr.code == RC_OK && nas_transport_pdu &&
        nas_transport_pdu->present == S1AP_S1AP_PDU_PR_initiatingMessage) {
        S1AP_InitiatingMessage_t *nas_init = nas_transport_pdu->choice.initiatingMessage;
        if (nas_init) {
            if (nas_init->value.present == S1AP_InitiatingMessage__value_PR_UplinkNASTransport) {
                is_uplink = true;
                classified = true;
                printf("[DEBUG] Classified NAS Transport as Uplink via ASN.1 decode\n");
            } else if (nas_init->value.present == S1AP_InitiatingMessage__value_PR_DownlinkNASTransport) {
                is_uplink = false;
                classified = true;
                printf("[DEBUG] Classified NAS Transport as Downlink via ASN.1 decode\n");
            }
        }
    }
    if (nas_transport_pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, nas_transport_pdu);
    }

    if (!classified) {
        printf("[DEBUG] Falling back to NAS Transport heuristic classification\n");
        for (size_t i = 4; i + 6 < len; ++i) {
            if (data[i] == 0x00 && data[i + 1] == 0x1A) {
                size_t nas_offset = i + 2;

                if (nas_offset < len) {
                    nas_offset++; /* Skip criticality (1 byte) */
                }

                uint32_t nas_length = 0;
                if (nas_offset < len) {
                    if (data[nas_offset] & 0x80) {
                        uint8_t length_octets = data[nas_offset] & 0x7F;
                        nas_offset++;
                        for (uint8_t j = 0; j < length_octets && nas_offset < len; ++j) {
                            nas_length = (nas_length << 8) | data[nas_offset++];
                        }
                    } else {
                        nas_length = data[nas_offset++];
                    }
                }

                bool found_nas = false;
                size_t search_limit = nas_length < 32 ? nas_length : 32;
                for (size_t search_offset = 0;
                     search_offset < search_limit && nas_offset + search_offset + 1 < len;
                     ++search_offset) {
                    if (data[nas_offset + search_offset] == 0x07) {
                        nas_offset += search_offset;
                        found_nas = true;
                        printf("[DEBUG] Found NAS-PDU at offset %zu (after %zu padding bytes)\n",
                               nas_offset, search_offset);
                        break;
                    }
                }

                if (!found_nas) {
                    printf("[WARN] Could not locate NAS-PDU start (0x07 not found)\n");
                    break;
                }

                if (nas_offset + 1 < len) {
                    uint8_t nas_pd = data[nas_offset];
                    uint8_t nas_msg_type = data[nas_offset + 1];

                    classified_nas_pd = nas_pd;
                    classified_nas_type = nas_msg_type;
                    nas_signature_known = true;

                    printf("[DEBUG] NAS Transport (proc=0x0D): NAS PD=0x%02X, Type=0x%02X (at offset %zu)\n",
                           nas_pd, nas_msg_type, nas_offset);

                    switch (nas_msg_type) {
                        case 0x53: /* Authentication Response */
                            is_uplink = true;
                            classified = true;
                            printf("[INFO] Detected UplinkNASTransport (Auth Response, type=0x53)\n");
                            break;
                        case 0x5C: /* Authentication Failure */
                            is_uplink = true;
                            classified = true;
                            printf("[INFO] Detected UplinkNASTransport (Authentication Failure, type=0x5C)\n");
                            break;
                        case 0x5E: /* Security Mode Complete */
                            is_uplink = true;
                            classified = true;
                            printf("[INFO] Detected UplinkNASTransport (Security Mode Complete, type=0x5E)\n");
                            break;
                        default:
                            is_uplink = false;
                            classified = true;
                            printf("[INFO] Detected DownlinkNASTransport (type=0x%02X)\n", nas_msg_type);
                            break;
                    }
                }
                break;
            }
        }
    }

    fflush(stdout);

    printf("[DEBUG] [PROC=0x0D] classification=%s (classified=%d)\n", is_uplink?"uplink":"downlink", classified);
    fflush(stdout);

    if (is_uplink) {
        if (nas_signature_known) {
            printf("[DEBUG] [PROC=0x0D] Uplink NAS summary: PD=0x%02X Type=0x%02X len=%zu\n",
                   classified_nas_pd, classified_nas_type, len);
        } else {
            printf("[DEBUG] [PROC=0x0D] Uplink NAS summary unavailable (len=%zu)\n", len);
        }
        fflush(stdout);
    }

    if (is_uplink) {
        /* Handle UplinkNASTransport */
        printf("[DEBUG] Processing UplinkNASTransport -> NGAP UplinkNASTransport\n");
        fflush(stdout);

        uint8_t ngap_data[512];
        size_t ngap_len = sizeof(ngap_data);

        int uplink_conv_rc = s1n2_convert_uplink_nas_transport(ctx, data, len, ngap_data, &ngap_len);
             printf("[DEBUG] [PROC=0x0D] Converter returned rc=%d for NAS type=0x%02X\n",
                 uplink_conv_rc, nas_signature_known ? classified_nas_type : 0x00);
             fflush(stdout);

             if (uplink_conv_rc == 0) {
            /* Send NGAP UplinkNASTransport to AMF with SCTP PPID=60 */
            ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                        NULL, 0, htonl(60), 0, 0, 0, 0);
            if (sent == (ssize_t)ngap_len) {
                printf("[INFO] UplinkNASTransport -> NGAP UplinkNASTransport sent (%zd bytes, PPID=60)\n", sent);
                fflush(stdout);

                /* Check if we need to send PDU Session Establishment Request */
                S1AP_S1AP_PDU_t *s1ap_pdu = NULL;
                asn_dec_rval_t s1ap_dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                                              (void **)&s1ap_pdu, data, len);
                if (s1ap_dr.code == RC_OK && s1ap_pdu &&
                    s1ap_pdu->present == S1AP_S1AP_PDU_PR_initiatingMessage &&
                    s1ap_pdu->choice.initiatingMessage &&
                    s1ap_pdu->choice.initiatingMessage->value.present ==
                    S1AP_InitiatingMessage__value_PR_UplinkNASTransport) {

                    S1AP_UplinkNASTransport_t *uplink_msg =
                        &s1ap_pdu->choice.initiatingMessage->value.choice.UplinkNASTransport;
                    long enb_ue_id_local = -1;

                    for (int i = 0; i < uplink_msg->protocolIEs.list.count; i++) {
                        S1AP_UplinkNASTransport_IEs_t *ie = uplink_msg->protocolIEs.list.array[i];
                        if (ie && ie->id == S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID &&
                            ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID) {
                            enb_ue_id_local = ie->value.choice.ENB_UE_S1AP_ID;
                            break;
                        }
                    }

                    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);

                    if (enb_ue_id_local >= 0) {
                        ue_id_mapping_t *ue_map = s1n2_context_find_mapping_by_ran(ctx, enb_ue_id_local);
                        if (ue_map && ue_map->send_pdu_session_establishment && ue_map->has_pending_pdu_session) {
                            printf("[INFO] [PDU Session] Detected Registration Complete, sending PDU Session Establishment Request\n");

                            uint8_t pdu_session_nas[512];
                            size_t pdu_session_len = sizeof(pdu_session_nas);
                            int ret = -1;

                            if (USE_UL_NAS_TRANSPORT_WRAPPER) {
                                printf("[INFO] [PDU Session] Using 5GMM UL NAS Transport wrapper (N1 SM container)\n");
                                ret = build_gmm_ul_nas_transport_with_n1_sm(
                                    pdu_session_nas, &pdu_session_len, ue_map,
                                    ue_map->pdu_session_id, ue_map->apn, 1,
                                    1
                                );
                            } else {
                                printf("[ERROR] UplinkNASTransport conversion failed (proc=0x0D, rc=%d)\n", uplink_conv_rc);
                                fflush(stdout);
                                printf("[INFO] [PDU Session] Using direct 5GSM (top-level EPD 0x2E)\n");
                                ret = build_pdu_session_establishment_request(
                                    pdu_session_nas, &pdu_session_len, ue_map,
                                    ue_map->pdu_session_id, ue_map->apn, 1
                                );
                            }

                            if (ret == 0 && pdu_session_len > 0) {
                                uint8_t pdu_session_ngap[512];
                                size_t pdu_session_ngap_len = sizeof(pdu_session_ngap);

                                if (build_ngap_uplink_nas(pdu_session_ngap, &pdu_session_ngap_len,
                                                          ue_map->amf_ue_ngap_id, ue_map->ran_ue_ngap_id,
                                                          pdu_session_nas, pdu_session_len,
                                                          ue_map->has_location_info ? ue_map->plmn_id : NULL,
                                                          ue_map->has_location_info ? ue_map->plmn_id_len : 0,
                                                          ue_map->has_location_info ? ue_map->cell_id : 0,
                                                          ue_map->has_location_info ? ue_map->tac : 0) == 0) {
                                    if (ue_map->has_location_info) {
                                        printf("[DEBUG] [PDU Session] UserLocationInformation: PLMN=%02X%02X%02X, Cell=0x%08X, TAC=0x%04X\n",
                                               ue_map->plmn_id[0], ue_map->plmn_id[1], ue_map->plmn_id[2],
                                               ue_map->cell_id, ue_map->tac);
                                    } else {
                                        printf("[WARN] [PDU Session] UserLocationInformation not included (no cached location)\n");
                                    }
                                    fflush(stdout);

                                    ssize_t pdu_sent = sctp_sendmsg(ctx->n2_fd, pdu_session_ngap, (size_t)pdu_session_ngap_len,
                                                                   NULL, 0, htonl(60), 0, 0, 0, 0);
                                    if (pdu_sent == (ssize_t)pdu_session_ngap_len) {
                                        printf("[INFO] [PDU Session] Sent PDU Session Establishment Request to AMF (%zd bytes)\n", pdu_sent);
                                        printf("[INFO] [PDU Session]   PDU Session ID=%u, DNN=%s, SST=1\n",
                                               ue_map->pdu_session_id, ue_map->apn);
                                        fflush(stdout);

                                        ue_map->send_pdu_session_establishment = false;
                                        ue_map->has_pending_pdu_session = false;
                                    } else {
                                        printf("[ERROR] [PDU Session] Failed to send PDU Session Establishment Request (ret=%zd, errno=%d)\n",
                                               pdu_sent, errno);
                                        fflush(stdout);
                                    }
                                } else {
                                    printf("[ERROR] [PDU Session] Failed to build NGAP UplinkNASTransport for PDU Session Establishment Request\n");
                                    fflush(stdout);
                                }
                            } else {
                                printf("[ERROR] [PDU Session] Failed to build PDU Session Establishment Request (ret=%d)\n", ret);
                                fflush(stdout);
                            }
                        }
                    }
                }
            } else {
                printf("[ERROR] Failed to send NGAP UplinkNASTransport via SCTP (ret=%zd, PPID=60, errno=%d)\n", sent, errno);
                fflush(stdout);
            }
        }
    } else {
        /* Handle DownlinkNASTransport */
        printf("[DEBUG] Processing DownlinkNASTransport -> NGAP DownlinkNASTransport\n");
        fflush(stdout);

        uint8_t ngap_data[512];
        size_t ngap_len = sizeof(ngap_data);

        if (s1n2_convert_downlink_nas_transport(ctx, data, len, ngap_data, &ngap_len) == 0) {
            ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                        NULL, 0, htonl(60), 0, 0, 0, 0);
            if (sent == (ssize_t)ngap_len) {
                printf("[INFO] DownlinkNASTransport -> NGAP DownlinkNASTransport sent (%zd bytes, PPID=60)\n", sent);
                fflush(stdout);
            } else {
                printf("[ERROR] Failed to send NGAP DownlinkNASTransport via SCTP (ret=%zd, PPID=60, errno=%d)\n", sent, errno);
                fflush(stdout);
            }
        }
    }
    return 0;
}
