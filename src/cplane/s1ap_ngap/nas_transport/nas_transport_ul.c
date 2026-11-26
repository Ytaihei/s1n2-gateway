#include "s1n2_log.h"
/**
 * @file nas_transport_ul.c
 * @brief Uplink NAS Transport conversion
 *
 * S1AP UplinkNASTransport -> NGAP (with 4G->5G NAS conversion)
 */
#include "internal/s1n2_converter_internal.h"
#include "nas_transport.h"
#include "security/security.h"

static int s1n2_send_auth_failure_initial_ue(s1n2_context_t *ctx,
                                             ue_id_mapping_t *ue_map,
                                             long enb_ue_id,
                                             const uint8_t *nas_pdu,
                                             size_t nas_len,
                                             const uint8_t *plmn_id,
                                             size_t plmn_id_len,
                                             uint32_t cell_id,
                                             uint16_t tac) {
    if (!ctx || !nas_pdu || nas_len == 0) {
        return -1;
    }

    long ran_id = (ue_map && ue_map->ran_ue_ngap_id > 0) ? ue_map->ran_ue_ngap_id : -1;
    if (ran_id <= 0) {
        if (enb_ue_id >= 0) {
            ran_id = enb_ue_id;
        } else if (ctx) {
            ran_id = s1n2_context_generate_ran_ue_ngap_id(ctx, -1);
        }
    }

    if (ue_map && ran_id > 0 && ue_map->ran_ue_ngap_id <= 0) {
        ue_map->ran_ue_ngap_id = ran_id;
    }

    char mcc[4];
    char mnc[4];
    s1n2_decode_plmn_tbcd(plmn_id, plmn_id_len, mcc, mnc);

    if (mcc[0] == '\0') {
        strcpy(mcc, "001");
    }
    if (mnc[0] == '\0') {
        strcpy(mnc, "01");
    }

    long tac_long = tac;
    if (tac_long <= 0) {
        const char *env_tac = getenv("S1N2_TAC");
        if (!env_tac || !*env_tac) env_tac = getenv("TAC");
        if (!env_tac || !*env_tac) env_tac = "1";
        tac_long = strtol(env_tac, NULL, 10);
    }

    uint8_t rrc_cause = NGAP_RRCEstablishmentCause_mo_Signalling;
    uint8_t ngap_payload[512];
    size_t ngap_len = sizeof(ngap_payload);
    int encoded = build_initial_ue_message(ngap_payload, &ngap_len,
                                           (uint32_t)((ran_id > 0) ? ran_id : 1),
                                           nas_pdu, nas_len,
                                           mcc, mnc, tac_long,
                                           cell_id, rrc_cause,
                                           false, 0, 0, 0, false);
    if (encoded <= 0) {
        LOG_ERROR("Fallback InitialUEMessage build failed for Auth Failure (rc=%d)\n", encoded);

        return -1;
    }

    ngap_len = (size_t)encoded;
    if (!ctx->n2_connected) {
        LOG_WARN("N2 not connected, cannot send fallback InitialUEMessage (len=%zu)\n", ngap_len);

        return -1;
    }

    ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_payload, ngap_len,
                                NULL, 0, htonl(60), 0, 0, 0, 0);
    if (sent != (ssize_t)ngap_len) {
        LOG_ERROR("Failed to send fallback InitialUEMessage (sent=%zd len=%zu errno=%d)\n",
               sent, ngap_len, errno);

        return -1;
    }

    LOG_INFO("Fallback InitialUEMessage sent for Auth Failure without AMF-UE-ID (RAN=%ld)\n",
           ran_id);

    return 0;
}

int s1n2_convert_uplink_nas_transport(s1n2_context_t *ctx, uint8_t *s1ap_data, size_t s1ap_len,
                                     uint8_t *ngap_data, size_t *ngap_len) {
    if (!s1ap_data || !ngap_data || !ngap_len || *ngap_len == 0)
        return -1;

    S1AP_S1AP_PDU_t *pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU, (void**)&pdu, s1ap_data, s1ap_len);
    if (dr.code != RC_OK || !pdu || pdu->present != S1AP_S1AP_PDU_PR_initiatingMessage) {
        LOG_ERROR("Failed to decode S1AP UplinkNASTransport (code=%d)\n", dr.code);

        if (pdu) ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return -1;
    }

    S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    if (!init || init->value.present != S1AP_InitiatingMessage__value_PR_UplinkNASTransport) {
        LOG_ERROR("S1AP message is not UplinkNASTransport\n");

        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return -1;
    }

    long mme_ue_id = -1;
    long enb_ue_id = -1;
    const uint8_t *nas_buf = NULL;
    size_t nas_len = 0;
    const uint8_t *plmn_id = NULL;
    size_t plmn_id_len = 0;
    uint32_t cell_id = 0;
    uint16_t tac = 0;

    S1AP_UplinkNASTransport_t *msg = &init->value.choice.UplinkNASTransport;
    for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
        S1AP_UplinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie) continue;

        switch (ie->id) {
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                if (ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID)
                    mme_ue_id = ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                if (ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID)
                    enb_ue_id = ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_NAS_PDU:
                if (ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_NAS_PDU &&
                    ie->value.choice.NAS_PDU.buf && ie->value.choice.NAS_PDU.size > 0) {
                    nas_buf = ie->value.choice.NAS_PDU.buf;
                    nas_len = ie->value.choice.NAS_PDU.size;
                }
                break;
            case S1AP_ProtocolIE_ID_id_EUTRAN_CGI:
                if (ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_EUTRAN_CGI) {
                    S1AP_EUTRAN_CGI_t *cgi = &ie->value.choice.EUTRAN_CGI;
                    if (cgi->pLMNidentity.buf && cgi->pLMNidentity.size > 0) {
                        plmn_id = cgi->pLMNidentity.buf;
                        plmn_id_len = cgi->pLMNidentity.size;
                    }
                    if (cgi->cell_ID.buf && cgi->cell_ID.size == 4) {
                        // Cell ID is 28 bits, extract from 4-byte buffer
                        cell_id = (cgi->cell_ID.buf[0] << 20) |
                                  (cgi->cell_ID.buf[1] << 12) |
                                  (cgi->cell_ID.buf[2] << 4) |
                                  (cgi->cell_ID.buf[3] >> 4);
                    }
                }
                break;
            case S1AP_ProtocolIE_ID_id_TAI:
                if (ie->value.present == S1AP_UplinkNASTransport_IEs__value_PR_TAI) {
                    S1AP_TAI_t *tai = &ie->value.choice.TAI;
                    if (tai->tAC.buf && tai->tAC.size == 2) {
                        tac = (tai->tAC.buf[0] << 8) | tai->tAC.buf[1];
                    }
                }
                break;
            default:
                break;
        }
    }

    LOG_DEBUG("[UL-IE] Extracted IDs: MME_UE_S1AP_ID=%ld ENB_UE_S1AP_ID=%ld NAS_PDU_len=%zu\n",
           mme_ue_id, enb_ue_id, nas_len);

    if (!nas_buf || nas_len == 0) {
        LOG_ERROR("S1AP UplinkNASTransport missing NAS-PDU\n");

        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return -1;
    }

    ue_id_mapping_t *ue_map = NULL;
    if (ctx) {
        if (enb_ue_id >= 0) {
            ue_map = s1n2_context_ensure_mapping_for_enb(ctx, enb_ue_id);
        }
        if (!ue_map && mme_ue_id >= 0) {
            ue_map = s1n2_context_find_mapping_by_amf(ctx, mme_ue_id);
        }
        if (ue_map) {
            LOG_DEBUG("[UPLINK-START] UplinkNASTransport: ENB=%ld, MME=%ld, nas_ul_count_5g=0x%08X\n",
                   enb_ue_id, mme_ue_id, ue_map->nas_ul_count_5g);
            if (enb_ue_id >= 0) {
                ue_map->enb_ue_s1ap_id = enb_ue_id;
            }
            if (mme_ue_id >= 0) {
                ue_map->mme_ue_s1ap_id = mme_ue_id;
                // Do NOT overwrite amf_ue_ngap_id with 4G mme_ue_id!
                // AMF-UE-NGAP-ID is assigned by AMF in DownlinkNASTransport
                // and should be preserved for subsequent UplinkNASTransport
            }
            if (ue_map->ran_ue_ngap_id <= 0 && enb_ue_id >= 0) {
                ue_map->ran_ue_ngap_id = enb_ue_id;
            }
            // Cache location information from S1AP EUTRAN-CGI and TAI
            if (plmn_id && plmn_id_len > 0 && plmn_id_len <= 3) {
                memcpy(ue_map->plmn_id, plmn_id, plmn_id_len);
                ue_map->plmn_id_len = plmn_id_len;
                ue_map->cell_id = cell_id;
                ue_map->tac = tac;
                ue_map->has_location_info = true;

            }
            ue_map->last_update = time(NULL);
        } else {
            LOG_DEBUG("[UPLINK-START] UplinkNASTransport: ENB=%ld, MME=%ld, ue_map=NULL\n",
                   enb_ue_id, mme_ue_id);
        }
    }

    // ============================================================
    // NAS Security Processing (Decryption/MAC verification)
    // ============================================================
    // 4G NAS Security Header structure (3GPP TS 24.301 Section 9.3.1):
    // Byte 0: Protocol discriminator (4 bits) | Security header type (4 bits)
    // Bytes 1-4: Message authentication code (MAC-I) [if integrity protected]
    // Byte 5: Sequence number [if integrity protected]
    // Byte 6: NAS message [after security header]

    uint8_t decrypted_nas_buf[512];
    const uint8_t *processed_nas_buf = nas_buf;
    size_t processed_nas_len = nas_len;
    bool tau_request_detected = false;
    uint8_t tau_eps_update_octet = 0;

    if (nas_4g_security_unwrap(ctx, ue_map, nas_buf, nas_len, decrypted_nas_buf,
                              sizeof(decrypted_nas_buf), &processed_nas_buf, &processed_nas_len) != 0) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return -1;
    }

    // ============================================================
    // TAU (Tracking Area Update) Detection
    // ============================================================
    // 4G NAS Message Type (TS 24.301 Section 9.8):
    // - 0x48: Tracking area update request
    // - 0x4a: Tracking area update accept
    // - 0x4b: Tracking area update complete
    // - 0x4c: Tracking area update reject

    if (ue_map && processed_nas_len > 0) {
        // Protocol discriminator + Security header type is in byte 0 (if security applied)
        // Message type is in byte 0 (plain NAS) or byte 1 (after security header)
        // For plain NAS: byte 0 = PD (lower 4 bits) + Security header type (upper 4 bits = 0)
        // Message type is in the SECOND byte of the NAS message (byte 1)
        uint8_t nas_message_type = 0;
        if (processed_nas_len >= 2) {
            nas_message_type = processed_nas_buf[1];  // Message type at offset 1
        }

        LOG_DEBUG("[TAU-CHECK] NAS Message Type: 0x%02X\n", nas_message_type);
        if (nas_message_type == 0x53) {
            LOG_DEBUG("[NAS-TYPE] Authentication Response detected\n");
        } else if (nas_message_type == 0x5C) {
            LOG_DEBUG("[NAS-TYPE] Authentication Failure detected (expects conversion to 5G type 0x59)\n");
            if (!ue_map) {
                LOG_WARN("[NAS-TYPE] UE mapping is NULL at Auth Failure (ENB=%ld MME=%ld)\n", enb_ue_id, mme_ue_id);
            } else if (ue_map->amf_ue_ngap_id <= 0) {
                LOG_WARN("[NAS-TYPE] Auth Failure before AMF-UE-NGAP-ID assignment (mapping incomplete)\n");
            }
        }

         if (nas_message_type == 0x48) {
             // TAU Request detected
             LOG_INFO("========== TAU REQUEST DETECTED ==========\n");
             LOG_INFO("UE is initiating Tracking Area Update procedure\n");
             LOG_INFO("Will terminate TAU inside converter (AMF not notified)\n");
             LOG_INFO("Existing PDU session/TEID mapping stays pinned locally\n");
             LOG_INFO("ENB=%ld, MME=%ld, AMF=%ld, RAN=%ld\n",
                 enb_ue_id, mme_ue_id, ue_map->amf_ue_ngap_id, ue_map->ran_ue_ngap_id);

            s1n2_context_mark_tau_start(ue_map);
            tau_request_detected = true;
            if (processed_nas_len >= 3) {
                tau_eps_update_octet = processed_nas_buf[2];
            }
        } else if (nas_message_type == 0x4b) {
            // TAU Complete detected
            if (ue_map->in_tau_procedure || ue_map->preserve_teid_mapping) {
                LOG_INFO("========== TAU COMPLETE DETECTED ==========\n");
                LOG_INFO("TAU procedure completed, TEID mappings preserved\n");

                s1n2_context_mark_tau_complete(ue_map);
            }
        }
    }

    // ============================================================
    // TAU termination: synthesize TAU Accept locally
    // ============================================================

    if (tau_request_detected && ctx && ue_map) {
        uint8_t tau_accept[256];
        size_t tau_accept_len = sizeof(tau_accept);
        bool tau_accept_sent = false;

        if (s1n2_build_tau_accept_nas(ctx, ue_map, tau_eps_update_octet,
                                      tau_accept, &tau_accept_len) == 0) {
            uint8_t s1ap_tau[512];
            size_t s1ap_tau_len = sizeof(s1ap_tau);
            long mme_for_tau = (ue_map->mme_ue_s1ap_id > 0) ? ue_map->mme_ue_s1ap_id :
                               ((mme_ue_id >= 0) ? mme_ue_id : 1);
            long enb_for_tau = (ue_map->enb_ue_s1ap_id > 0) ? ue_map->enb_ue_s1ap_id :
                               ((enb_ue_id >= 0) ? enb_ue_id : 1);

            if (build_s1ap_downlink_nas(s1ap_tau, &s1ap_tau_len, mme_for_tau,
                                        enb_for_tau, tau_accept, tau_accept_len) == 0) {
                if (ctx->s1c_fd > 0) {
                    ssize_t sent = sctp_sendmsg(ctx->s1c_fd, s1ap_tau, s1ap_tau_len,
                                                NULL, 0, htonl(18), 0, 0, 0, 0);
                    if (sent == (ssize_t)s1ap_tau_len) {
                        tau_accept_sent = true;
                        LOG_INFO("Sent synthetic TAU Accept to eNB (len=%zu, ENB=%ld, MME=%ld)\n",
                               tau_accept_len, enb_for_tau, mme_for_tau);
                    } else {
                        LOG_ERROR("Failed to send TAU Accept via S1C (ret=%zd, errno=%d)\n",
                               sent, errno);
                    }
                } else {
                    LOG_ERROR("Cannot send TAU Accept - S1C socket unavailable\n");
                }
            } else {
                LOG_ERROR("Failed to wrap TAU Accept NAS inside S1AP Downlink message\n");
            }

        } else {
            LOG_ERROR("Could not build TAU Accept NAS payload (len cap=%zu)\n",
                   tau_accept_len);

        }

        if (tau_accept_sent) {
            s1n2_context_mark_tau_complete(ue_map);
            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
            *ngap_len = 0;
            return 0;
        } else {
            LOG_WARN("TAU Accept send failed, falling back to legacy conversion path\n");

        }
    }

    // ============================================================
    // NAS Conversion (4G -> 5G)
    // ============================================================

    // Try to convert 4G NAS to 5G NAS
    uint8_t nas_5g_buf[512];
    size_t nas_5g_len = sizeof(nas_5g_buf);
    const uint8_t *final_nas_buf = processed_nas_buf;
    size_t final_nas_len = processed_nas_len;

    LOG_DEBUG("S1AP UplinkNASTransport: attempting NAS conversion (4G->5G)\n");

    LOG_INFO(" (len=%zu)\n", processed_nas_len);

    if (ue_map && ue_map->registration_complete_sent && processed_nas_len >= 2 &&
        processed_nas_buf[0] == 7 && processed_nas_buf[1] == 0x43) {
        /* EPS attach completes locally; 5GS registration was completed earlier. */
        *ngap_len = 0;
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return 0;
    }
    if (convert_4g_nas_to_5g(ctx, ue_map, (uint8_t *)processed_nas_buf, processed_nas_len, nas_5g_buf, &nas_5g_len) == 0) {
        LOG_INFO("UplinkNASTransport: 4G NAS converted to 5G NAS (4G len=%zu, 5G len=%zu)\n",
               processed_nas_len, nas_5g_len);

        final_nas_buf = nas_5g_buf;
        final_nas_len = nas_5g_len;
    } else {
        LOG_WARN("UplinkNASTransport: NAS conversion failed, using original 4G NAS\n");
        // Keep original 4G NAS if conversion fails
    }

    // Use AMF-UE-NGAP-ID from UE mapping context (assigned by AMF in DownlinkNASTransport)
    // NOT from 4G MME-UE-S1AP-ID!
    long amf_ue_ngap_id = (ue_map && ue_map->amf_ue_ngap_id > 0) ? ue_map->amf_ue_ngap_id : 0;
    long ran_ue_ngap_id = (ue_map && ue_map->ran_ue_ngap_id > 0) ? ue_map->ran_ue_ngap_id :
                          ((enb_ue_id >= 0) ? enb_ue_id : 1);
    uint8_t nas_message_type_for_map = (processed_nas_len >= 2) ? processed_nas_buf[1] : 0;
        uint32_t final_nas_crc = s1n2_crc32(final_nas_buf, final_nas_len);
        LOG_DEBUG("[UL-MAP] Mapping state: amf_ue_ngap_id=%ld ran_ue_ngap_id=%ld ue_map=%p nas_msg_type=0x%02X final_crc=0x%08X\n",
            amf_ue_ngap_id, ran_ue_ngap_id, (void*)ue_map, nas_message_type_for_map, final_nas_crc);
    if (nas_message_type_for_map == 0x5C && amf_ue_ngap_id <= 0) {
        LOG_WARN("[UL-MAP] Auth Failure observed before AMF-UE-ID assignment, attempting fallback InitialUEMessage\n");
    }

    if (amf_ue_ngap_id <= 0) {
        bool attempted_fallback = (nas_message_type_for_map == 0x5C);
        if (attempted_fallback) {
            const int fallback_rc = s1n2_send_auth_failure_initial_ue(
                ctx,
                ue_map,
                enb_ue_id,
                final_nas_buf,
                final_nas_len,
                plmn_id,
                plmn_id_len,
                cell_id,
                tac);
            ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
            if (fallback_rc == 0) {
                LOG_INFO("Auth Failure forwarded via fallback InitialUEMessage path\n");

                return 0;
            }
            LOG_ERROR("Fallback InitialUEMessage path failed (rc=%d), dropping NAS\n", fallback_rc);

            return -1;
        }

        LOG_WARN("AMF-UE-NGAP-ID not assigned yet, cannot send UplinkNASTransport (ENB=%ld)\n", enb_ue_id);
        LOG_INFO("This message should have been sent as InitialUEMessage, not UplinkNASTransport\n");
        LOG_WARN("Drop detail: NAS type=0x%02X SHT=0x%02X final_len=%zu final_crc=0x%08X\n",
               nas_message_type_for_map, (nas_buf[0] >> 4), final_nas_len, final_nas_crc);

        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
        return -1;
    }

    size_t out_len = *ngap_len;
    LOG_DEBUG("[NGAP-BUILD] Requesting UplinkNASTransport build (AMF-UE=%ld, RAN-UE=%ld, NAS=%zu, CRC=0x%08X, msg_type=0x%02X)\n",
           amf_ue_ngap_id, ran_ue_ngap_id, final_nas_len, final_nas_crc,
           (final_nas_len >= 2) ? final_nas_buf[1] : 0x00);

    int rc = build_ngap_uplink_nas(ngap_data, &out_len, amf_ue_ngap_id, ran_ue_ngap_id,
                                    final_nas_buf, final_nas_len,
                                    plmn_id, plmn_id_len, cell_id, tac);
    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);

    if (rc != 0) {
        LOG_ERROR("Failed to build NGAP UplinkNASTransport\n");

        return -1;
    }

    *ngap_len = out_len;
        uint32_t ngap_crc = s1n2_crc32(ngap_data, out_len);
        LOG_INFO("Converted S1AP UplinkNASTransport to NGAP (AMF-UE=%ld, RAN-UE=%ld, NAS=%zu bytes, NGAP_CRC=0x%08X)\n",
            amf_ue_ngap_id, ran_ue_ngap_id, final_nas_len, ngap_crc);

    // Note: Piggybacked Registration Request is now included within Security Mode Complete
    // as NAS message container IE (IEI 0x71) by convert_4g_nas_to_5g()
    // See 3GPP TS 24.501 § 8.2.28 Security mode complete + § 9.11.3.24 NAS message container

    return 0;
}
