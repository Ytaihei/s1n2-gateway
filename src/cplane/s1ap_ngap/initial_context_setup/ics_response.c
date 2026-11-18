#include "s1n2_log.h"
/*
 * s1n2_ics.c – Initial Context Setup response conversion
 */
#include "internal/s1n2_converter_internal.h"

int s1n2_convert_initial_context_setup_response(uint8_t *s1ap_data, size_t s1ap_len,
                                               uint8_t *ngap_data, size_t *ngap_len,
                                               s1n2_context_t *ctx) {
    if (!s1ap_data || !ngap_data || !ngap_len || *ngap_len == 0) {
        LOG_ERROR("Invalid parameters for InitialContextSetupResponse conversion\n");
        return -1;
    }

    // Parse S1AP InitialContextSetupResponse
    S1AP_S1AP_PDU_t *s1ap_pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU, (void**)&s1ap_pdu, s1ap_data, s1ap_len);

    if (dr.code != RC_OK || !s1ap_pdu) {
        LOG_ERROR("Failed to decode S1AP InitialContextSetupResponse\n");
        if (s1ap_pdu) ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
        return -1;
    }

    // Verify it's a successful outcome for InitialContextSetup
    if (s1ap_pdu->present != S1AP_S1AP_PDU_PR_successfulOutcome ||
        !s1ap_pdu->choice.successfulOutcome ||
        s1ap_pdu->choice.successfulOutcome->procedureCode != S1AP_ProcedureCode_id_InitialContextSetup) {
        LOG_ERROR("Not a valid S1AP InitialContextSetupResponse\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
        return -1;
    }

    S1AP_SuccessfulOutcome_t *succ = s1ap_pdu->choice.successfulOutcome;
    S1AP_InitialContextSetupResponse_t *s1ap_resp = &succ->value.choice.InitialContextSetupResponse;

    // Extract IEs from S1AP response
    long mme_ue_s1ap_id = -1;
    long enb_ue_s1ap_id = -1;
    S1AP_E_RABSetupListCtxtSURes_t *erab_setup_list = NULL;

    for (int i = 0; i < s1ap_resp->protocolIEs.list.count; i++) {
        S1AP_InitialContextSetupResponseIEs_t *ie = s1ap_resp->protocolIEs.list.array[i];
        if (!ie) continue;

        switch (ie->id) {
        case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
            if (ie->value.present == S1AP_InitialContextSetupResponseIEs__value_PR_MME_UE_S1AP_ID) {
                mme_ue_s1ap_id = ie->value.choice.MME_UE_S1AP_ID;
                LOG_DEBUG("S1AP ICS Response: MME_UE_S1AP_ID=%ld\n", mme_ue_s1ap_id);
            }
            break;
        case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
            if (ie->value.present == S1AP_InitialContextSetupResponseIEs__value_PR_ENB_UE_S1AP_ID) {
                enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;
                LOG_DEBUG("S1AP ICS Response: ENB_UE_S1AP_ID=%ld\n", enb_ue_s1ap_id);
            }
            break;
        case S1AP_ProtocolIE_ID_id_E_RABSetupListCtxtSURes:
            if (ie->value.present == S1AP_InitialContextSetupResponseIEs__value_PR_E_RABSetupListCtxtSURes) {
                erab_setup_list = &ie->value.choice.E_RABSetupListCtxtSURes;
                LOG_DEBUG("S1AP ICS Response: E-RAB Setup List with %d items\n",
                       erab_setup_list->list.count);
            }
            break;
        default:
            break;
        }
    }

    if (mme_ue_s1ap_id == -1 || enb_ue_s1ap_id == -1) {
        LOG_ERROR("Missing required IEs in S1AP InitialContextSetupResponse\n");
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
        return -1;
    }

    // Build NGAP InitialContextSetupResponse
    NGAP_NGAP_PDU_t *ngap_pdu = calloc(1, sizeof(NGAP_NGAP_PDU_t));
    if (!ngap_pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
        return -1;
    }

    ngap_pdu->present = NGAP_NGAP_PDU_PR_successfulOutcome;
    ngap_pdu->choice.successfulOutcome = calloc(1, sizeof(NGAP_SuccessfulOutcome_t));
    if (!ngap_pdu->choice.successfulOutcome) goto fail;

    NGAP_SuccessfulOutcome_t *ngap_succ = ngap_pdu->choice.successfulOutcome;
    ngap_succ->procedureCode = NGAP_ProcedureCode_id_InitialContextSetup;
    ngap_succ->criticality = NGAP_Criticality_reject;
    ngap_succ->value.present = NGAP_SuccessfulOutcome__value_PR_InitialContextSetupResponse;

    NGAP_InitialContextSetupResponse_t *ngap_resp = &ngap_succ->value.choice.InitialContextSetupResponse;

    // Add AMF-UE-NGAP-ID (use MME ID)
    NGAP_InitialContextSetupResponseIEs_t *ie = calloc(1, sizeof(NGAP_InitialContextSetupResponseIEs_t));
    if (!ie) goto fail;
    ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present = NGAP_InitialContextSetupResponseIEs__value_PR_AMF_UE_NGAP_ID;
    if (asn_long2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, mme_ue_s1ap_id) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie);
        free(ie);
        goto fail;
    }
    ASN_SEQUENCE_ADD(&ngap_resp->protocolIEs.list, ie);

    // Add RAN-UE-NGAP-ID (use ENB ID)
    ie = calloc(1, sizeof(NGAP_InitialContextSetupResponseIEs_t));
    if (!ie) goto fail;
    ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present = NGAP_InitialContextSetupResponseIEs__value_PR_RAN_UE_NGAP_ID;
    ie->value.choice.RAN_UE_NGAP_ID = enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&ngap_resp->protocolIEs.list, ie);

    // Build PDUSessionResourceSetupListCxtRes to notify AMF/SMF/UPF of s1n2's N3 tunnel info
    // This enables UPF to send downlink GTP-U packets to s1n2
    // If E-RAB setup list exists, build minimal PDUSessionResourceSetupListCxtRes
    if (erab_setup_list && erab_setup_list->list.count > 0) {
        LOG_INFO("E-RAB Setup List present with %d items (building PDUSessionResourceSetupListCxtRes)\n",
               erab_setup_list->list.count);

        NGAP_InitialContextSetupResponseIEs_t *ie_ps_list = calloc(1, sizeof(NGAP_InitialContextSetupResponseIEs_t));
        if (!ie_ps_list) goto fail;
        ie_ps_list->id = NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListCxtRes;
        ie_ps_list->criticality = NGAP_Criticality_reject;
        ie_ps_list->value.present = NGAP_InitialContextSetupResponseIEs__value_PR_PDUSessionResourceSetupListCxtRes;

        NGAP_PDUSessionResourceSetupListCxtRes_t *ps_list = &ie_ps_list->value.choice.PDUSessionResourceSetupListCxtRes;

        for (int i = 0; i < erab_setup_list->list.count; i++) {
            // Each list element is a SingleContainer wrapping E_RABSetupItemCtxtSURes
            S1AP_ProtocolIE_SingleContainer_8146P6_t *sc = (S1AP_ProtocolIE_SingleContainer_8146P6_t *)erab_setup_list->list.array[i];
            if (!sc) continue;

            if (sc->value.present != S1AP_E_RABSetupItemCtxtSUResIEs__value_PR_E_RABSetupItemCtxtSURes) {
                continue;
            }

            S1AP_E_RABSetupItemCtxtSURes_t *rab_item = &sc->value.choice.E_RABSetupItemCtxtSURes;

            // Extract IPv4 transportLayerAddress (BIT STRING) and GTP-TEID (OCTET STRING)
            uint32_t enb_ip_be = 0; // network byte order
            if (rab_item->transportLayerAddress.size >= 4) {
                memcpy(&enb_ip_be, rab_item->transportLayerAddress.buf, 4);
            }
            uint32_t enb_teid_be = 0;  // eNB's uplink TEID (for downlink traffic from core)
            if (rab_item->gTP_TEID.size >= 4 && rab_item->gTP_TEID.buf) {
                memcpy(&enb_teid_be, rab_item->gTP_TEID.buf, 4);
            }
            uint32_t enb_teid = ntohl(enb_teid_be);

            // Map E-RAB ID -> PDU Session ID (MVP: same numeric value)
            long pdu_session_id = (long)rab_item->e_RAB_ID;
            if (pdu_session_id <= 0) pdu_session_id = 1;

            // Register TEID mapping for downlink traffic (UPF -> s1n2 -> eNB)
            if (ctx && enb_teid != 0) {
                ue_id_mapping_t *ue_map_for_teid = s1n2_context_find_mapping_by_enb(ctx, enb_ue_s1ap_id);
                if (ue_map_for_teid && ue_map_for_teid->has_upf_n3_info) {
                    s1n2_uplane_register_dl_mapping(enb_teid, enb_ip_be,
                        ue_map_for_teid->upf_n3_teid, ue_map_for_teid->upf_n3_ip,
                        (uint8_t)pdu_session_id, (uint16_t)rab_item->e_RAB_ID);
                } else {
                    LOG_WARN("[TEID-MAP] Cannot register mapping: UPF N3 info not available (ENB-UE-ID=%ld)\n", enb_ue_s1ap_id);
                }
            }

            // Build PDUSessionResourceSetupItemCxtRes
            NGAP_PDUSessionResourceSetupItemCxtRes_t *ps_item = calloc(1, sizeof(NGAP_PDUSessionResourceSetupItemCxtRes_t));
            if (!ps_item) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }
            // NGAP_PDUSessionID_t is NativeInteger (long), assign directly
            ps_item->pDUSessionID = (NGAP_PDUSessionID_t)pdu_session_id;

            // Build PDUSessionResourceSetupResponseTransfer
            NGAP_PDUSessionResourceSetupResponseTransfer_t transfer;
            memset(&transfer, 0, sizeof(transfer));

            // dLQosFlowPerTNLInformation.uPTransportLayerInformation = gTPTunnel(transportLayerAddress, gTP-TEID)
            NGAP_UPTransportLayerInformation_t *uplt = &transfer.dLQosFlowPerTNLInformation.uPTransportLayerInformation;
            uplt->present = NGAP_UPTransportLayerInformation_PR_gTPTunnel;
            uplt->choice.gTPTunnel = calloc(1, sizeof(NGAP_GTPTunnel_t));
            if (!uplt->choice.gTPTunnel) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }

            // Fill GTPTunnel
            NGAP_GTPTunnel_t *gtp = uplt->choice.gTPTunnel;
            // TransportLayerAddress (BIT STRING) - set IPv4 32 bits
            gtp->transportLayerAddress.buf = calloc(1, 4);
            if (!gtp->transportLayerAddress.buf) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }

            // TRANSPARENT PROXY MODE: Report s1n2's own IP but with eNB's TEID
            // This tells UPF to send downlink packets to s1n2, which will forward to eNB
            uint32_t report_ip_be = enb_ip_be;  // Will be changed to s1n2 IP below
            uint32_t report_teid_be = enb_teid_be;  // Use eNB TEID

            if (ctx) {
                // Report s1n2's S1-U interface IP as the uplink tunnel endpoint
                // This ensures UPF sends downlink packets to s1n2 (not directly to eNB)
                report_ip_be = ctx->s1u_addr.sin_addr.s_addr;

                char s1n2_ip_str[INET_ADDRSTRLEN];
                char enb_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &report_ip_be, s1n2_ip_str, sizeof(s1n2_ip_str));
                inet_ntop(AF_INET, &enb_ip_be, enb_ip_str, sizeof(enb_ip_str));

                LOG_INFO("TRANSPARENT PROXY: Reporting uplink tunnel to AMF:\n");
                LOG_INFO("  - IP: %s (s1n2 S1-U interface, will proxy to eNB %s)\n", s1n2_ip_str, enb_ip_str);
                LOG_INFO("  - TEID: 0x%08x (eNB's uplink TEID)\n", ntohl(report_teid_be));
                LOG_INFO("  - Rationale: UPF sends downlink to s1n2, s1n2 forwards to eNB\n");
            } else {
                LOG_WARN("No context provided, using eNB IP/TEID directly\n");
            }

            memcpy(gtp->transportLayerAddress.buf, &report_ip_be, 4);
            gtp->transportLayerAddress.size = 4;
            gtp->transportLayerAddress.bits_unused = 0;

            // GTP-TEID (OCTET STRING, 4 bytes)
            if (OCTET_STRING_fromBuf(&gtp->gTP_TEID, (const char *)&report_teid_be, 4) != 0) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }

            // Get QFI from UE mapping context (extracted from AMF's NGAP ICS Request)
            // If not available, use default QFI=9 (QCI=9 mapping) as fallback
            long qfi = 9; // Default fallback
            if (ctx) {
                ue_id_mapping_t *ue_map_for_qfi = s1n2_context_find_recent_security(ctx);
                if (ue_map_for_qfi && ue_map_for_qfi->qfi > 0) {
                    qfi = ue_map_for_qfi->qfi;
                    LOG_DEBUG("Using QFI=%ld from UE mapping context (ENB=%ld)\n",
                           qfi, ue_map_for_qfi->enb_ue_s1ap_id);
                } else {
                    LOG_DEBUG("Using default QFI=%ld (no cached QFI in UE context)\n", qfi);
                }
            } else {
                LOG_WARN("No context provided, using default QFI=%ld\n", qfi);
            }

            // associatedQosFlowList: add QFI
            NGAP_AssociatedQosFlowItem_t *qfi_item = calloc(1, sizeof(NGAP_AssociatedQosFlowItem_t));
            if (!qfi_item) {
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }
            qfi_item->qosFlowIdentifier = qfi;
            ASN_SEQUENCE_ADD(&transfer.dLQosFlowPerTNLInformation.associatedQosFlowList.list, qfi_item);

            LOG_DEBUG("Added QoS Flow to associatedQosFlowList: QFI=%ld\n", qfi);

            // Encode transfer as APER and wrap into OCTET STRING
            void *xfer_buf = NULL;
            ssize_t xfer_bytes = aper_encode_to_new_buffer(&asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, NULL,
                                                           &transfer, &xfer_buf);
            if (xfer_bytes <= 0 || !xfer_buf) {
                LOG_ERROR("Failed to encode PDUSessionResourceSetupResponseTransfer\n");
                // Free allocated substructures
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, &transfer);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }

            if (OCTET_STRING_fromBuf(&ps_item->pDUSessionResourceSetupResponseTransfer,
                                     (const char *)xfer_buf, (size_t)xfer_bytes) != 0) {
                LOG_ERROR("Failed to set OCTET STRING for PDUSessionResourceSetupResponseTransfer\n");
                free(xfer_buf);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, &transfer);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemCxtRes, ps_item);
                free(ps_item);
                ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_InitialContextSetupResponseIEs, ie_ps_list);
                free(ie_ps_list);
                goto fail;
            }

            // Free temporary transfer structure content and its dynamic buffer
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupResponseTransfer, &transfer);
            free(xfer_buf);

            // Add item to the PDUSessionResourceSetupListCxtRes
            ASN_SEQUENCE_ADD(&ps_list->list, ps_item);
        }

        // Add the PDUSessionResourceSetupListCxtRes IE to NGAP response
        ASN_SEQUENCE_ADD(&ngap_resp->protocolIEs.list, ie_ps_list);
    }

    // Encode NGAP PDU
    if (asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, ngap_pdu, NULL, NULL) != 0) {
        LOG_ERROR("NGAP InitialContextSetupResponse constraint check failed\n");
        goto fail;
    }

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, ngap_pdu, ngap_data, *ngap_len);
    if (er.encoded == -1) {
        LOG_ERROR("Failed to encode NGAP InitialContextSetupResponse\n");
        goto fail;
    }

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *ngap_len) {
        LOG_ERROR("NGAP InitialContextSetupResponse too large for buffer\n");
        goto fail;
    }
    *ngap_len = bytes;

    LOG_INFO("Converted S1AP InitialContextSetupResponse -> NGAP (%zu bytes)\n", bytes);
    LOG_INFO("IDs: MME/AMF=%ld, ENB/RAN=%ld, E-RABs=%d\n",
           mme_ue_s1ap_id, enb_ue_s1ap_id,
           erab_setup_list ? erab_setup_list->list.count : 0);

    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, ngap_pdu);
    return 0;

fail:
    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, s1ap_pdu);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, ngap_pdu);
    return -1;
}
