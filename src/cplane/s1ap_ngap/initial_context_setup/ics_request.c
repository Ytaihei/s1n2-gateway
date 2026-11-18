#include "registration/registration.h"
#include "registration/registration_bridge.h"
#include "security/security.h"
#include "s1n2_log.h"
/**
 * @file ics_request.c
 * @brief NGAP InitialContextSetupRequest handler
 *
 * Handles NGAP InitialContextSetupRequest from AMF:
 *   - Parses ICS IEs (AMF/RAN UE IDs, PDU Session setup, NAS PDU)
 *   - Extracts UPF N3 tunnel info and QFI
 *   - Processes pending S1AP ICS Response queue
 *   - Builds and forwards S1AP InitialContextSetupRequest to eNB
 *
 * Extracted from ngap_dispatcher.c during Phase 2 refactoring.
 */

#include "s1n2_converter.h"
#include "internal/s1n2_converter_internal.h"
#include "ics.h"
#include "gtp_tunnel.h"

#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_InitialContextSetupRequest.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_PDUSessionResourceSetupListCxtReq.h"
#include "NGAP_PDUSessionResourceSetupItemCxtReq.h"
#include "NGAP_PDUSessionResourceSetupRequestTransfer.h"
#include "NGAP_UPTransportLayerInformation.h"
#include "NGAP_GTPTunnel.h"
#include "NGAP_QosFlowSetupRequestList.h"
#include "NGAP_QosFlowSetupRequestItem.h"
#include "NGAP_NAS-PDU.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <time.h>
#include <math.h>

/**
 * Handle NGAP InitialContextSetupRequest
 *
 * This function processes the ICS Request from AMF, extracts tunnel info and QFI,
 * handles pending ICS responses, and builds/sends S1AP ICS Request to eNB.
 *
 * @param ctx S1N2 context
 * @param init Decoded NGAP InitiatingMessage (must be InitialContextSetupRequest)
 * @return 0 if handled, -1 if not handled
 */
int ics_request_handle_ngap_ics(s1n2_context_t *ctx, void *init_msg) {
    NGAP_InitiatingMessage_t *init = (NGAP_InitiatingMessage_t *)init_msg;
    if (!ctx || !init) return -1;

    NGAP_InitialContextSetupRequest_t *ics = &init->value.choice.InitialContextSetupRequest;
    LOG_DEBUG("NGAP InitialContextSetupRequest detected (proc=%ld) - IE count: %ld\n",
           (long)init->procedureCode, ics ? ics->protocolIEs.list.count : -1L);

    long amf_ue_id = -1;
    long ran_ue_id = -1;
    int pdu_sess_count = 0;
    int nas_pdu_len = 0;
    const uint8_t *nas_ptr = NULL;
    const NGAP_NAS_PDU_t *session_nas = NULL;

    if (ics) {
        LOG_DEBUG("NGAP ICS: Entering IE loop (count=%d)\n", ics->protocolIEs.list.count);
        for (int i = 0; i < ics->protocolIEs.list.count; i++) {
            NGAP_InitialContextSetupRequestIEs_t *ie = ics->protocolIEs.list.array[i];
            if (!ie) continue;
            LOG_DEBUG(" NGAP ICS IE[%d]: ID=%ld, present=%d\n", i, ie->id, ie->value.present);
            switch (ie->id) {
                case NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID:
                    if (ie->value.present == NGAP_InitialContextSetupRequestIEs__value_PR_AMF_UE_NGAP_ID) {
                        long tmp = -1;
                        if (asn_INTEGER2long(&ie->value.choice.AMF_UE_NGAP_ID, &tmp) == 0) {
                            amf_ue_id = tmp;
                        } else {
                            LOG_WARN(" NGAP ICS: Failed to decode AMF_UE_NGAP_ID\n");
                        }
                    }
                    break;
                case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
                    if (ie->value.present == NGAP_InitialContextSetupRequestIEs__value_PR_RAN_UE_NGAP_ID) {
                        ran_ue_id = ie->value.choice.RAN_UE_NGAP_ID;
                    }
                    break;
                case NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListCxtReq:
                    if (ie->value.present == NGAP_InitialContextSetupRequestIEs__value_PR_PDUSessionResourceSetupListCxtReq) {
                        NGAP_PDUSessionResourceSetupListCxtReq_t *lst = &ie->value.choice.PDUSessionResourceSetupListCxtReq;
                        pdu_sess_count = lst->list.count;
                        LOG_DEBUG(" NGAP ICS: PDUSessionResourceSetupListCxtReq count=%d\n", pdu_sess_count);
                        for (int j = 0; j < lst->list.count; j++) {
                            struct NGAP_PDUSessionResourceSetupItemCxtReq *item = lst->list.array[j];
                            if (!item) continue;
                            if (item->nAS_PDU) session_nas = item->nAS_PDU;
                            int sid = (int)item->pDUSessionID;
                            int xfer_len = (int)item->pDUSessionResourceSetupRequestTransfer.size;
                            LOG_DEBUG("  - PDU Session ID=%d, Transfer size=%d bytes\n", sid, xfer_len);

                            // Decode PDUSessionResourceSetupRequestTransfer to extract UPF N3 tunnel info
                            NGAP_PDUSessionResourceSetupRequestTransfer_t *transfer = NULL;
                            asn_dec_rval_t dec_ret = aper_decode_complete(NULL,
                                &asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer,
                                (void **)&transfer,
                                item->pDUSessionResourceSetupRequestTransfer.buf,
                                item->pDUSessionResourceSetupRequestTransfer.size);

                            if (dec_ret.code == RC_OK && transfer) {
                                LOG_DEBUG("    Decoded PDUSessionResourceSetupRequestTransfer successfully\n");

                                // Extract UL-NGU-UP-TNLInformation (UPF's downlink tunnel to s1n2)
                                for (int t = 0; t < transfer->protocolIEs.list.count; t++) {
                                    NGAP_PDUSessionResourceSetupRequestTransferIEs_t *xfer_ie = transfer->protocolIEs.list.array[t];
                                    if (!xfer_ie) continue;

                                    if (xfer_ie->id == NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation &&
                                        xfer_ie->value.present == NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_UPTransportLayerInformation) {

                                        NGAP_UPTransportLayerInformation_t *ul_tnl = &xfer_ie->value.choice.UPTransportLayerInformation;
                                        if (ul_tnl->present == NGAP_UPTransportLayerInformation_PR_gTPTunnel && ul_tnl->choice.gTPTunnel) {
                                            NGAP_GTPTunnel_t *gtp_tunnel = ul_tnl->choice.gTPTunnel;

                                            // Extract UPF IP address (Transport Layer Address)
                                            uint32_t upf_ip_be = 0;
                                            if (gtp_tunnel->transportLayerAddress.size >= 4) {
                                                memcpy(&upf_ip_be, gtp_tunnel->transportLayerAddress.buf, 4);
                                            }

                                            // Extract UPF downlink TEID (GTP-TEID)
                                            uint32_t upf_dl_teid_be = 0;
                                            if (gtp_tunnel->gTP_TEID.size >= 4) {
                                                memcpy(&upf_dl_teid_be, gtp_tunnel->gTP_TEID.buf, 4);
                                            }

                                            LOG_INFO("    UPF N3 Downlink Tunnel: IP=%s, TEID=0x%08x\n",
                                                   inet_ntoa(*(struct in_addr*)&upf_ip_be), ntohl(upf_dl_teid_be));

                                            // Store UPF N3 tunnel info in the UE mapping context
                                            ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
                                            if (!ue_map) {
                                                for (size_t mi = 0; mi < S1N2_MAX_UE_MAPPINGS; ++mi) {
                                                    if (ctx->ue_mappings[mi].in_use) {
                                                        ue_map = &ctx->ue_mappings[mi];
                                                        break;
                                                    }
                                                }
                                            }
                                            // Delegate UPF N3 storage and deferred TEID mapping to U-Plane module
                                            s1n2_uplane_store_upf_n3_and_map(ctx, ue_map, upf_ip_be,
                                                ntohl(upf_dl_teid_be), (uint8_t)sid,
                                                ue_map ? ue_map->ics_e_rab_id : 5);
                                        }
                                    }

                                    // Extract QoSFlowSetupRequestList to get QFI values
                                    if (xfer_ie->id == NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList &&
                                        xfer_ie->value.present == NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_QosFlowSetupRequestList) {

                                        NGAP_QosFlowSetupRequestList_t *qos_list = &xfer_ie->value.choice.QosFlowSetupRequestList;
                                        LOG_DEBUG("    QosFlowSetupRequestList count=%d\n", qos_list->list.count);

                                        // Extract first QFI (typically only one QoS flow for data)
                                        if (qos_list->list.count > 0 && qos_list->list.array[0]) {
                                            NGAP_QosFlowSetupRequestItem_t *qos_item = qos_list->list.array[0];
                                            long extracted_qfi = qos_item->qosFlowIdentifier;
                                            LOG_INFO("    Extracted QFI=%ld from QosFlowSetupRequestList\n", extracted_qfi);

                                            // Store QFI in UE mapping context
                                            ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
                                            if (!ue_map) {
                                                for (size_t mi = 0; mi < S1N2_MAX_UE_MAPPINGS; ++mi) {
                                                    if (ctx->ue_mappings[mi].in_use) {
                                                        ue_map = &ctx->ue_mappings[mi];
                                                        break;
                                                    }
                                                }
                                            }
                                            if (ue_map) {
                                                ue_map->qfi = (uint8_t)extracted_qfi;
                                                LOG_INFO("    Stored QFI=%d in UE context (ENB=%ld)\n",
                                                       ue_map->qfi, ue_map->enb_ue_s1ap_id);

                                                // Update QFI in existing TEID mappings that were created before QFI was known
                                                if (ue_map->has_s1n2_uplink_teid && ue_map->s1n2_s1u_uplink_teid > 0) {
                                                    gtp_tunnel_update_mapping_qfi(ue_map->s1n2_s1u_uplink_teid, (uint8_t)extracted_qfi);
                                                }
                                                if (ue_map->has_enb_s1u_info && ue_map->enb_s1u_teid > 0) {
                                                    gtp_tunnel_update_mapping_qfi(ue_map->enb_s1u_teid, (uint8_t)extracted_qfi);
                                                }
                                            }
                                        }
                                    }
                                }

                                ASN_STRUCT_FREE(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, transfer);
                            } else {
                                LOG_WARN("    Failed to decode PDUSessionResourceSetupRequestTransfer (code=%d)\n", dec_ret.code);


                            }
                        }
                    }
                    break;
                case NGAP_ProtocolIE_ID_id_NAS_PDU:
                    if (ie->value.present == NGAP_InitialContextSetupRequestIEs__value_PR_NAS_PDU) {
                        OCTET_STRING_t *nas = &ie->value.choice.NAS_PDU;
                        nas_pdu_len = nas->size;
                        nas_ptr = nas->buf;
                        LOG_DEBUG(" NGAP ICS: NAS-PDU present, len=%d\n", nas_pdu_len);


                    }
                    break;
                default:
                    break;
            }
        }
    }

    // Resolve MME/eNB IDs from mapping
    long mme_ue_id = (amf_ue_id >= 0) ? amf_ue_id : 1;
    long enb_ue_id = (ran_ue_id >= 0) ? ran_ue_id : 1;
    ue_id_mapping_t *ue_map = NULL;
    if (ctx) {
        if (ran_ue_id >= 0) ue_map = s1n2_context_find_mapping_by_ran(ctx, ran_ue_id);
        if (!ue_map && amf_ue_id >= 0) ue_map = s1n2_context_find_mapping_by_amf(ctx, amf_ue_id);
        if (ue_map) {
            if ((session_nas || nas_ptr) && !ue_map->has_pdu_ipv4) {
                uint8_t plain_buffer[2048], mac[4], seq;
                const uint8_t *plain;
                size_t plain_len;
                bool has_mac;
                if (nas_5g_security_unwrap(session_nas ? session_nas->buf : nas_ptr,
                    session_nas ? session_nas->size : (size_t)nas_pdu_len, ue_map,
                    &plain, &plain_len, plain_buffer, sizeof(plain_buffer), mac, &has_mac, &seq) != 0 ||
                    s1n2_cache_pdu_address(ue_map, plain, plain_len) != 0) {
                    LOG_ERROR("Invalid PDU Session Accept in NGAP context setup");
                    return -1;
                }
            }
            // Mark that AMF has requested ICS
            ue_map->amf_ics_requested = true;

            // If we have cached S1AP ICS Response, convert to NGAP now (with correct QFI) and send
            if (ue_map->has_pending_s1ap_ics && ue_map->pending_s1ap_ics_len > 0) {
                LOG_INFO("[ICS] Converting cached S1AP InitialContextSetupResponse to NGAP with QFI=%u\n", ue_map->qfi);
                uint8_t ngap_data[512];
                size_t ngap_len = sizeof(ngap_data);
                if (s1n2_convert_initial_context_setup_response(ue_map->pending_s1ap_ics,
                                                               ue_map->pending_s1ap_ics_len,
                                                               ngap_data, &ngap_len, ctx) == 0) {
                    ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, (size_t)ngap_len,
                                                NULL, 0, htonl(60), 0, 0, 0, 0);
                    if (sent == (ssize_t)ngap_len) {
                        LOG_INFO("InitialContextSetupResponse -> NGAP InitialContextSetupResponse sent (%zd bytes, PPID=60)\n", sent);
                        ue_map->has_pending_s1ap_ics = false;
                        ue_map->pending_s1ap_ics_len = 0;
                        return 0; // handled
                    } else {
                        LOG_WARN("Failed to send NGAP InitialContextSetupResponse via SCTP (ret=%zd, PPID=60, errno=%d: %s)\n",
                               sent, errno, strerror(errno));
                    }
                } else {
                    LOG_ERROR("Failed to convert cached S1AP ICS Response to NGAP\n");
                }
            }
            // Legacy: If we have a pending NGAP ICS (old implementation), send it now
            else if (ue_map->has_pending_ngap_ics && ue_map->pending_ngap_ics_len > 0) {
                LOG_INFO("[ICS] Sending previously queued NGAP InitialContextSetupResponse upon AMF request\n");
                ssize_t sent = sctp_sendmsg(ctx->n2_fd, ue_map->pending_ngap_ics, (size_t)ue_map->pending_ngap_ics_len,
                                            NULL, 0, htonl(60), 0, 0, 0, 0);
                if (sent == (ssize_t)ue_map->pending_ngap_ics_len) {
                    LOG_INFO("InitialContextSetupResponse -> NGAP InitialContextSetupResponse sent (%zd bytes, PPID=60)\n", sent);
                    ue_map->has_pending_ngap_ics = false;
                    ue_map->pending_ngap_ics_len = 0;
                    return 0; // handled
                } else {
                    LOG_WARN("Failed to send queued NGAP InitialContextSetupResponse via SCTP (ret=%zd, PPID=60, errno=%d: %s)\n",
                           sent, errno, strerror(errno));
                }
            }
            if (ue_map->enb_ue_s1ap_id > 0) enb_ue_id = ue_map->enb_ue_s1ap_id;
            if (ue_map->mme_ue_s1ap_id > 0) mme_ue_id = ue_map->mme_ue_s1ap_id;
            // Suppress duplicate ICS if already completed or in-flight
            if (ue_map->ics_completed) {
                LOG_INFO("[ICS] Already completed for UE (ENB=%ld) - no S1AP ICS needed\n", enb_ue_id);
                return 0; // handled
            }
            if (ue_map->ics_sent) {
                double elapsed = difftime(time(NULL), ue_map->ics_sent_time);
                if (elapsed < 10.0) {
                    LOG_INFO("[ICS] In-flight (sent %.1fs ago) for UE (ENB=%ld); ignoring NGAP ICS request\n", elapsed, enb_ue_id);
                    return 0; // handled
                }
            }
        }
    }

    // Pick S1-U IPv4 and TEID for default bearer
    uint32_t s1u_ip_be = 0;
    uint32_t s1u_teid_be = 0;
    uint8_t e_rab_id = 5;
    s1n2_uplane_select_s1u_endpoint(ctx, ue_map, &s1u_ip_be, &s1u_teid_be, &e_rab_id);

    /*
     * Deferred uplink TEID mapping:
     * store_upf_n3_and_map was called during IE-loop parsing (above), but at
     * that time has_s1n2_uplink_teid was still false because
     * select_s1u_endpoint had not yet run.  Now that both pieces are ready,
     * call store_upf_n3_and_map again so the S1-U 0x00000001 → UPF N3 TEID
     * mapping gets registered into the tunnel table.
     */
    if (ue_map && ue_map->has_upf_n3_info && ue_map->has_s1n2_uplink_teid &&
        ue_map->s1n2_s1u_uplink_teid > 0 && ue_map->upf_n3_teid > 0) {
        LOG_INFO("[ICS] Re-registering deferred uplink TEID mapping after S1-U endpoint selection\n");
        s1n2_uplane_store_upf_n3_and_map(ctx, ue_map,
            ue_map->upf_n3_ip, ue_map->upf_n3_teid,
            (uint8_t)ue_map->pdu_session_id,
            ue_map->ics_e_rab_id ? ue_map->ics_e_rab_id : e_rab_id);
    }

    uint8_t attach_nas[512];
    size_t attach_len = sizeof(attach_nas);
    if (ue_map && ue_map->pending_registration_accept_len) {
        if (!ue_map->has_pdu_ipv4 || registration_accept_convert_5g_to_4g(
            ue_map->pending_registration_accept, ue_map->pending_registration_accept_len,
            attach_nas, &attach_len, ue_map) != 0) {
            LOG_ERROR("Cannot build EPS attach before the core assigns an IPv4 address");
            return -1;
        }
        nas_ptr = attach_nas;
        nas_pdu_len = (int)attach_len;
    }

    uint8_t s1ap_buf[2048];
    size_t s1ap_len = sizeof(s1ap_buf);
    if (build_s1ap_initial_context_setup_request(s1ap_buf, &s1ap_len,
                                                mme_ue_id, enb_ue_id,
                                                nas_ptr, nas_pdu_len,
                                                e_rab_id, s1u_ip_be, s1u_teid_be,
                                                (ue_map && ue_map->has_kenb) ? ue_map->kenb : NULL) == 0) {
        if (ctx->s1c_fd <= 0) {
            LOG_ERROR("S1C not connected; cannot send S1AP ICS\n");

            return -1;
        }
        ssize_t sent = sctp_sendmsg(ctx->s1c_fd, s1ap_buf, s1ap_len, NULL, 0, htonl(18), 0, 0, 0, 0);
        if (sent == (ssize_t)s1ap_len) {
            LOG_INFO("NGAP ICS bridged to S1AP InitialContextSetupRequest (%zd bytes)\n", sent);
            if (ue_map) {
                ue_map->ics_sent = true;
                ue_map->ics_sent_time = time(NULL);
                ue_map->ics_e_rab_id = e_rab_id;
                ue_map->pending_registration_accept_len = 0;
            }
        } else {
            LOG_ERROR("Failed to send S1AP ICS (ret=%zd, errno=%d: %s)\n", sent, errno, strerror(errno));
        }

        return 0; // handled
    } else {
        LOG_ERROR("Failed to build S1AP InitialContextSetupRequest\n");

        return -1;
    }
}
