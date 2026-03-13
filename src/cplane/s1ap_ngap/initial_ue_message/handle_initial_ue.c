/**
 * @file handle_initial_ue.c
 * @brief InitialUEMessage handler (procedure code 0x0C)
 *
 * ASN.1 decode of S1AP InitialUEMessage, UE mapping management,
 * NAS-PDU extraction (ASN.1 + IE parsing + heuristic fallback),
 * UE Network Capability caching, 4G→5G NAS conversion,
 * NGAP InitialUEMessage build and SCTP send.
 */
#include "internal/s1n2_converter_internal.h"
#include "nas_transport/nas_transport.h"
#include "s1ap_dispatch_handlers.h"

int s1ap_dispatch_initial_ue(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    printf("[DEBUG] InitialUEMessage (S1AP) detected (proc=0x0C, len=%zu)\n", len);
    fflush(stdout);

    /* Print detailed hexdump of the entire S1AP InitialUEMessage */
    printf("[HEX] S1AP InitialUEMessage (%zu): ", len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (len % 16 != 0) printf("\n");
    fflush(stdout);

    /* Parse S1AP InitialUEMessage and extract parameters */
    long enb_ue_s1ap_id = -1;
    uint32_t ran_ue_ngap_id = 0;
    uint8_t nas_pdu[256] = {0};
    size_t nas_pdu_len = 0;
    char mcc[4] = "001", mnc[4] = "01";
    long tac = 1;
    uint32_t nr_cell_id = 1;
    uint8_t rrc_cause = 0;
    bool include_s_tmsi = false;
    uint32_t amf_set_id = 0, amf_pointer = 0, fiveg_tmsi = 0;
    bool ue_context_requested = false;

    bool nas_from_asn1 = false;

    S1AP_S1AP_PDU_t *initial_pdu = NULL;
    asn_dec_rval_t init_dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                                   (void**)&initial_pdu, data, len);
    if (init_dr.code == RC_OK && initial_pdu &&
        initial_pdu->present == S1AP_S1AP_PDU_PR_initiatingMessage) {
        S1AP_InitiatingMessage_t *init = initial_pdu->choice.initiatingMessage;
        if (init && init->value.present == S1AP_InitiatingMessage__value_PR_InitialUEMessage) {
            S1AP_InitialUEMessage_t *msg = &init->value.choice.InitialUEMessage;
            for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
                S1AP_InitialUEMessage_IEs_t *ie = msg->protocolIEs.list.array[i];
                if (!ie) continue;

                switch (ie->id) {
                    case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_ENB_UE_S1AP_ID) {
                            enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;
                        }
                        break;
                    case S1AP_ProtocolIE_ID_id_NAS_PDU:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_NAS_PDU &&
                            ie->value.choice.NAS_PDU.buf && ie->value.choice.NAS_PDU.size > 0) {
                            printf("[DEBUG] ASN.1 NAS_PDU.size=%zu, first 8 bytes of buf: ", ie->value.choice.NAS_PDU.size);
                            for (size_t dbg = 0; dbg < 8 && dbg < ie->value.choice.NAS_PDU.size; ++dbg) {
                                printf("%02X ", ie->value.choice.NAS_PDU.buf[dbg]);
                            }
                            printf("\n");
                            fflush(stdout);

                            /* Skip APER length byte if present */
                            const uint8_t *nas_start_ptr = ie->value.choice.NAS_PDU.buf;
                            size_t nas_actual_len = ie->value.choice.NAS_PDU.size;

                            if (nas_actual_len > 1 && nas_start_ptr[0] >= 0x70 && nas_start_ptr[0] <= 0x7F) {
                                uint8_t aper_len = nas_start_ptr[0];
                                if (aper_len + 1 == nas_actual_len) {
                                    printf("[DEBUG] Detected APER length byte 0x%02X, skipping it\n", aper_len);
                                    nas_start_ptr++;
                                    nas_actual_len--;
                                }
                            }

                            nas_pdu_len = nas_actual_len > sizeof(nas_pdu) ? sizeof(nas_pdu) : nas_actual_len;
                            memcpy(nas_pdu, nas_start_ptr, nas_pdu_len);
                            nas_from_asn1 = true;

                            printf("[DEBUG] After APER check: copied %zu bytes, first 4: %02X %02X %02X %02X\n",
                                   nas_pdu_len, nas_pdu[0], nas_pdu[1], nas_pdu[2], nas_pdu[3]);
                            fflush(stdout);
                        }
                        break;
                    case S1AP_ProtocolIE_ID_id_TAI:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_TAI) {
                            S1AP_TAI_t *tai = &ie->value.choice.TAI;
                            if (tai->pLMNidentity.buf && tai->pLMNidentity.size >= 3) {
                                mcc[0] = '0' + (tai->pLMNidentity.buf[0] & 0x0F);
                                mcc[1] = '0' + ((tai->pLMNidentity.buf[0] >> 4) & 0x0F);
                                mcc[2] = '0' + (tai->pLMNidentity.buf[1] & 0x0F);
                                mnc[0] = '0' + ((tai->pLMNidentity.buf[2] & 0x0F));
                                mnc[1] = '0' + ((tai->pLMNidentity.buf[2] >> 4) & 0x0F);
                                if (tai->pLMNidentity.size >= 3) {
                                    uint8_t mnc_digit3 = (tai->pLMNidentity.buf[1] >> 4) & 0x0F;
                                    if (mnc_digit3 != 0x0F) {
                                        mnc[2] = '0' + mnc_digit3;
                                        mnc[3] = '\0';
                                    }
                                }
                            }
                            if (tai->tAC.buf && tai->tAC.size > 0) {
                                tac = 0;
                                size_t tac_len = tai->tAC.size;
                                if (tac_len > 3) {
                                    tac_len = 3; /* NGAP TAC は 24bit まで */
                                }
                                for (size_t idx = 0; idx < tac_len; ++idx) {
                                    tac = (tac << 8) | tai->tAC.buf[idx];
                                }
                            }
                        }
                        break;
                    case S1AP_ProtocolIE_ID_id_RRC_Establishment_Cause:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_RRC_Establishment_Cause) {
                            rrc_cause = (uint8_t)ie->value.choice.RRC_Establishment_Cause;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    } else {
        printf("[WARN] Failed to decode InitialUEMessage via ASN.1 (code=%d)\n", init_dr.code);
        fflush(stdout);
    }

    if (initial_pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, initial_pdu);
    }

    ue_id_mapping_t *ue_map = NULL;
    if (enb_ue_s1ap_id > 0) {
        ue_map = s1n2_context_ensure_mapping_for_enb(ctx, enb_ue_s1ap_id);
        if (ue_map) {
            ran_ue_ngap_id = (uint32_t)ue_map->ran_ue_ngap_id;
            printf("[INFO] Tracking UE mapping ENB=%ld -> RAN=%u\n", enb_ue_s1ap_id, ran_ue_ngap_id);

            /* Fresh RRC connection from UE. Ensure ICS state is cleared. */
            if (ue_map->ics_sent || ue_map->ics_completed || ue_map->ics_failed || ue_map->ics_e_rab_id) {
                ue_map->ics_sent = false;
                ue_map->ics_completed = false;
                ue_map->ics_failed = false;
                ue_map->ics_e_rab_id = 0;
                printf("[INFO] [ICS] Cleared ICS state on InitialUEMessage (ENB=%ld)\n", enb_ue_s1ap_id);
            }
        } else {
            ran_ue_ngap_id = (uint32_t)ctx->next_ran_ue_ngap_id++;
            printf("[WARN] Using fallback RAN-UE-NGAP-ID=%u for ENB UE ID %ld\n",
                   ran_ue_ngap_id, enb_ue_s1ap_id);
        }
    } else {
        ran_ue_ngap_id = (uint32_t)ctx->next_ran_ue_ngap_id++;
        printf("[WARN] ENB_UE_S1AP_ID unavailable, assigning new RAN-UE-NGAP-ID=%u\n",
               ran_ue_ngap_id);
    }
    fflush(stdout);

    /* Enhanced NAS-PDU extraction — look for S1AP NAS-PDU IE (ID=26, 0x1A) */
    bool found_nas = false;
    if (!nas_from_asn1) {
    for (size_t i = 4; i + 6 < len; ++i) {
        /* Look for IE ID 26 (0x1A) — NAS-PDU */
        if (data[i] == 0x00 && data[i+1] == 0x1A) {
            printf("[DEBUG] Found NAS-PDU IE at offset %zu\n", i);
            if (i + 3 < len) {
                size_t length_offset = i + 3;
                uint32_t ie_length = 0;

                printf("[DEBUG] Criticality byte at offset %zu: 0x%02X\n", i+2, data[i+2]);
                printf("[DEBUG] Length byte at offset %zu: 0x%02X\n", length_offset, data[length_offset]);

                /* Parse length (can be 1-4 bytes in APER) */
                if (data[length_offset] & 0x80) {
                    /* Multi-byte length */
                    uint8_t length_octets = data[length_offset] & 0x7F;
                    if (length_octets <= 4 && length_offset + length_octets < len) {
                        for (uint8_t j = 0; j < length_octets; ++j) {
                            ie_length = (ie_length << 8) | data[length_offset + 1 + j];
                        }
                        size_t nas_start = length_offset + 1 + length_octets;
                        if (nas_start + ie_length <= len) {
                            nas_pdu_len = ie_length > sizeof(nas_pdu) ? sizeof(nas_pdu) : ie_length;
                            memcpy(nas_pdu, &data[nas_start], nas_pdu_len);
                            found_nas = true;
                            printf("[DEBUG] Extracted NAS-PDU via IE parsing (len=%zu)\n", nas_pdu_len);
                            break;
                        }
                    }
                } else {
                    /* Single-byte length */
                    ie_length = data[length_offset];
                    size_t nas_start = length_offset + 1;
                    if (nas_start + ie_length <= len) {
                        nas_pdu_len = ie_length > sizeof(nas_pdu) ? sizeof(nas_pdu) : ie_length;
                        memcpy(nas_pdu, &data[nas_start], nas_pdu_len);
                        found_nas = true;
                        printf("[DEBUG] Extracted NAS-PDU via IE parsing (len=%zu)\n", nas_pdu_len);
                        break;
                    }
                }
            }
        }
    }
    } /* End of if (!nas_from_asn1) */

    /* Fallback: Try to extract NAS-PDU from S1AP (heuristic: look for 0x7E) */
    if (!nas_from_asn1 && !found_nas) {
        for (size_t i = 0; i + 1 < len; ++i) {
            if (data[i] == 0x7E) {
                nas_pdu_len = (len - i) > sizeof(nas_pdu) ? sizeof(nas_pdu) : (len - i);
                memcpy(nas_pdu, &data[i], nas_pdu_len);
                found_nas = true;
                printf("[DEBUG] Extracted NAS-PDU via 0x7E heuristic (len=%zu)\n", nas_pdu_len);
                break;
            }
        }
    }

    if (!nas_from_asn1 && !found_nas) {
        printf("[WARN] Could not locate NAS-PDU in S1AP InitialUEMessage\n");
        fflush(stdout);
        return 0;
    }

    if (!nas_from_asn1 && found_nas) {
        printf("[DEBUG] Extracted NAS-PDU from S1AP (len=%zu)\n", nas_pdu_len);
    } else if (nas_from_asn1) {
        printf("[DEBUG] Extracted NAS-PDU via ASN.1 parse (len=%zu)\n", nas_pdu_len);
    }

    /* Extract and cache 4G UE Network Capability from Attach Request (IEI 0x58) */
    printf("[TRACE] UE capability extraction checkpoint: ue_map=%p, nas_pdu_len=%zu\n", (void*)ue_map, nas_pdu_len);
    if (ue_map && nas_pdu_len >= 12) {
        printf("[TRACE] Checking NAS PDU: byte[0]=0x%02X, byte[1]=0x%02X\n", nas_pdu[0], nas_pdu[1]);
        if ((nas_pdu[0] & 0x0F) == 0x07 && nas_pdu[1] == 0x41) {
            printf("[DEBUG] ★★★ Detected 4G Attach Request, parsing UE Network Capability ★★★\n");
            fflush(stdout);

            if (nas_pdu_len < 4) {
                printf("[TRACE] NAS PDU too short for Attach Request\n");
            } else {
                size_t offset = 3;

                /* EPS mobile identity (IMSI) */
                if (offset < nas_pdu_len) {
                    uint8_t imsi_len = nas_pdu[offset];
                    offset++;
                    offset += imsi_len;
                    printf("[TRACE] Parsed IMSI (len=%u), next offset=%zu\n", imsi_len, offset);
                }

                /* Next should be UE network capability */
                if (offset < nas_pdu_len) {
                    uint8_t next_byte = nas_pdu[offset];
                    size_t cap_offset = offset;

                    if (next_byte == 0x58) {
                        printf("[TRACE] Found IEI 0x58 at offset %zu\n", offset);
                        cap_offset = offset + 1;
                    } else {
                        printf("[TRACE] No IEI found, assuming LV format at offset %zu (byte=0x%02X)\n", offset, next_byte);
                    }

                    /* Parse UE network capability (LV or V part of TLV) */
                    if (cap_offset < nas_pdu_len) {
                        uint8_t ue_net_cap_len = nas_pdu[cap_offset];
                        if (cap_offset + 1 + ue_net_cap_len <= nas_pdu_len &&
                            ue_net_cap_len > 0 && ue_net_cap_len <= S1N2_MAX_UE_SECURITY_CAP_LEN) {
                            memcpy(ue_map->ue_network_cap_4g, &nas_pdu[cap_offset + 1], ue_net_cap_len);
                            ue_map->ue_network_cap_4g_len = ue_net_cap_len;
                            ue_map->has_ue_network_cap_4g = true;

                            printf("[INFO] ★★★ Cached 4G UE Network Capability (len=%u): ", ue_net_cap_len);
                            for (uint8_t j = 0; j < ue_net_cap_len; j++) {
                                printf("%02X ", ue_map->ue_network_cap_4g[j]);
                            }
                            printf(" ★★★\n");
                            fflush(stdout);
                        } else {
                            printf("[TRACE] Invalid UE network capability length: %u\n", ue_net_cap_len);
                        }
                    }
                }
            }
        } else {
            printf("[TRACE] Not 4G Attach Request (PD&0x0F)=0x%02X, MSG=0x%02X\n", nas_pdu[0] & 0x0F, nas_pdu[1]);
        }
    } else {
        printf("[TRACE] Skipping UE capability extraction (ue_map is NULL or nas_pdu too short)\n");
    }
    fflush(stdout);

    /* ★ CRITICAL DEBUG: Force NAS conversion path */
    printf("=== CRITICAL DEBUG: ENTERING NAS CONVERSION PATH ===\n");
    printf("[UNIQUE] MODIFIED CODE ACTIVE - This message should appear if code is updated!\n");
    fflush(stdout);

    /* Convert S1AP InitialUEMessage to NGAP InitialUEMessage with NAS conversion */
    uint8_t ngap_data[512];
    size_t ngap_len = sizeof(ngap_data);

    printf("[CRITICAL] Calling dynamic NGAP InitialUEMessage builder with NAS conversion\n");
    fflush(stdout);

    /* Convert 4G NAS-PDU to 5G NAS-PDU before building NGAP message */
    uint8_t converted_nas[256];
    size_t converted_nas_len = 0;
    const uint8_t *final_nas_pdu = nas_pdu;
    size_t final_nas_pdu_len = nas_pdu_len;

    printf("[DEBUG] About to convert NAS-PDU: original length=%zu\n", nas_pdu_len);
    printf("[DEBUG] NAS-PDU buffer (first 16 bytes): ");
    for (size_t dbg_i = 0; dbg_i < (nas_pdu_len < 16 ? nas_pdu_len : 16); ++dbg_i) {
        printf("%02X ", nas_pdu[dbg_i]);
    }
    printf("\n");
    fflush(stdout);
    if (convert_4g_nas_to_5g(ctx, ue_map, (uint8_t *)nas_pdu, nas_pdu_len, converted_nas, &converted_nas_len) == 0) {
        printf("[INFO] 4G->5G NAS-PDU conversion successful (4G:%zu bytes -> 5G:%zu bytes)\n", nas_pdu_len, converted_nas_len);
        final_nas_pdu = converted_nas;
        final_nas_pdu_len = converted_nas_len;

        /* Extract IMSI from 5G Registration Request and cache it */
        if (ctx && final_nas_pdu_len > 3 && final_nas_pdu[2] == 0x41) {
            char extracted_imsi[16] = {0};
            if (s1n2_extract_imsi_from_5g_registration_request(final_nas_pdu, final_nas_pdu_len,
                                                           extracted_imsi, sizeof(extracted_imsi)) == 0) {
                printf("[INFO] Extracted IMSI from Registration Request: %s\n", extracted_imsi);

                ue_id_mapping_t *ue_map = s1n2_context_ensure_mapping_for_enb(ctx, enb_ue_s1ap_id);
                if (ue_map && extracted_imsi[0] != '\0') {
                    strncpy(ue_map->imsi, extracted_imsi, sizeof(ue_map->imsi) - 1);
                    ue_map->imsi[sizeof(ue_map->imsi) - 1] = '\0';
                    printf("[SUCCESS] Cached IMSI in UE mapping: %s (ENB-UE-ID=%ld, RAN-UE-ID=%ld)\n",
                           ue_map->imsi, ue_map->enb_ue_s1ap_id, ue_map->ran_ue_ngap_id);

                    /* Cache 5G Registration Request for piggybacked re-transmission
                     * after Security Mode Complete (3GPP TS 24.501 § 5.5.1.2.4) */
                    if (final_nas_pdu_len <= 512) {
                        memcpy(ue_map->cached_registration_request, final_nas_pdu, final_nas_pdu_len);
                        ue_map->cached_reg_req_len = (int)final_nas_pdu_len;
                        printf("[INFO] Cached Registration Request (len=%d) for UE ENB_UE_S1AP_ID=%ld\n",
                               ue_map->cached_reg_req_len, enb_ue_s1ap_id);
                        fflush(stdout);
                    } else {
                        printf("[WARN] Registration Request too large to cache (%zu > 512 bytes)\n",
                               final_nas_pdu_len);
                        fflush(stdout);
                    }
                }
            }
        }
    } else {
        printf("[WARN] 4G->5G NAS-PDU conversion failed, using original 4G NAS-PDU\n");
    }

    /* Use dynamic builder with converted 5G NAS-PDU */
    int result = build_initial_ue_message(ngap_data, &ngap_len,
        ran_ue_ngap_id, final_nas_pdu, final_nas_pdu_len,
        mcc, mnc, tac, nr_cell_id, rrc_cause,
        include_s_tmsi, amf_set_id, amf_pointer, fiveg_tmsi,
        ue_context_requested);

    if (result > 0) {
        printf("[INFO] Dynamic NGAP InitialUEMessage builder successful (encoded %d bytes)\n", result);
        ngap_len = (size_t)result;
    } else {
        printf("[ERROR] Dynamic NGAP InitialUEMessage builder failed (result=%d)\n", result);
    }

    if (result > 0) {
        printf("[INFO] Dynamic InitialUEMessage encoded (%zu bytes)\n", ngap_len);
        fflush(stdout);

        if (!ctx->n2_connected) {
            printf("[WARN] N2 connection not established, dropping InitialUEMessage\n");
            fflush(stdout);
            return 0;
        }

        /* Send NGAP InitialUEMessage to AMF with SCTP PPID=60 */
        ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_data, ngap_len,
                                    NULL, 0, htonl(60), 0, 0, 0, 0);
        if (sent == (ssize_t)ngap_len) {
            printf("[INFO] InitialUEMessage -> NGAP InitialUEMessage sent (%zd bytes, PPID=60)\n", sent);
            fflush(stdout);
        } else {
            printf("[ERROR] Failed to send NGAP InitialUEMessage via SCTP (ret=%zd, PPID=60, errno=%d)\n", sent, errno);
            fflush(stdout);
        }
    } else {
        printf("[ERROR] Failed to build dynamic InitialUEMessage (result=%d)\n", result);
        fflush(stdout);
    }
    return 0;
}
