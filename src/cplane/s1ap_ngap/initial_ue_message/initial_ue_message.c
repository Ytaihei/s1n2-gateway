#include "s1n2_log.h"
/*
 * initial_ue_message.c – S1AP InitialUEMessage to NGAP conversion
 */
#include "internal/s1n2_converter_internal.h"

int s1n2_convert_initial_ue_message(uint8_t *s1ap_data, size_t s1ap_len,
                                    uint8_t *ngap_data, size_t *ngap_len) {
    if (!ngap_data || !ngap_len || *ngap_len < 256) {
        return -1;
    }

    long enb_ue_s1ap_id = -1;
    uint8_t nas_ie_copy[256] = {0};
    size_t nas_ie_copy_len = 0;

    S1AP_S1AP_PDU_t *decoded_pdu = NULL;
    asn_dec_rval_t s1_dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                                (void **)&decoded_pdu, s1ap_data, s1ap_len);
    if (s1_dr.code == RC_OK && decoded_pdu &&
        decoded_pdu->present == S1AP_S1AP_PDU_PR_initiatingMessage) {
        S1AP_InitiatingMessage_t *init = decoded_pdu->choice.initiatingMessage;
        if (init && init->value.present == S1AP_InitiatingMessage__value_PR_InitialUEMessage) {
            S1AP_InitialUEMessage_t *msg = &init->value.choice.InitialUEMessage;
            for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
                S1AP_InitialUEMessage_IEs_t *ie = msg->protocolIEs.list.array[i];
                if (!ie) {
                    continue;
                }

                switch (ie->id) {
                    case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_ENB_UE_S1AP_ID) {
                            enb_ue_s1ap_id = ie->value.choice.ENB_UE_S1AP_ID;
                        }
                        break;
                    case S1AP_ProtocolIE_ID_id_NAS_PDU:
                        if (ie->value.present == S1AP_InitialUEMessage_IEs__value_PR_NAS_PDU &&
                            ie->value.choice.NAS_PDU.buf && ie->value.choice.NAS_PDU.size > 0) {
                            size_t copy_len = ie->value.choice.NAS_PDU.size;
                            if (copy_len > sizeof(nas_ie_copy)) {
                                copy_len = sizeof(nas_ie_copy);
                            }
                            memcpy(nas_ie_copy, ie->value.choice.NAS_PDU.buf, copy_len);
                            nas_ie_copy_len = copy_len;
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    } else {
        LOG_WARN("Failed to decode InitialUEMessage for eNB UE ID (code=%d)\n", s1_dr.code);

    }

    if (decoded_pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, decoded_pdu);
    }

    if (enb_ue_s1ap_id > 0) {
        LOG_INFO("Extracted eNB_UE_S1AP_ID=%ld from InitialUEMessage\n", enb_ue_s1ap_id);
    } else {
        enb_ue_s1ap_id = 1;
        LOG_WARN("Using fallback eNB_UE_S1AP_ID=%ld\n", enb_ue_s1ap_id);
    }

    uint8_t initial_ue[] = {
        0x00, 0x0F, 0x40, 0x7C,
        0x00, 0x00, 0x00, 0x0F,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x74,
        0x00, 0x00, 0x00, 0x70,
        0x00, 0x00, 0x00, 0x55,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x26,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x1C,
        0x7E, 0x00, 0x41, 0x79,
        0x00, 0x0B, 0xF2, 0x10,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x79,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x0C,
        0x00, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x89,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x08,
        0x00, 0x00, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x00
    };

    ssize_t idx_ranue_id = -1;
    size_t nas_start = 0;
    size_t nas_length = 0;

    for (size_t i = 0; i + 1 < s1ap_len; ++i) {
        if (s1ap_data[i] == 0x7E) {
            nas_start = i;
            nas_length = (s1ap_len - i) > 64 ? 64 : (s1ap_len - i);
            LOG_DEBUG("Detected 5G NAS-PDU at offset %zu (0x7E)\n", i);
            break;
        } else if (s1ap_data[i] == 0x0C && (i + 1) < s1ap_len && s1ap_data[i + 1] == 0x07) {
            nas_start = i;
            nas_length = (s1ap_len - i) > 64 ? 64 : (s1ap_len - i);
            LOG_DEBUG("Detected 4G Attach Request at offset %zu (0x0C 0x07)\n", i);
            break;
        } else if ((s1ap_data[i] & 0x0F) == 0x07 && (i + 1) < s1ap_len) {
            uint8_t msg_type = s1ap_data[i + 1];
            LOG_DEBUG("Detected 4G EMM message at offset %zu (PD=0x07, msg_type=0x%02X)\n",
                   i, msg_type);
            // Convert common 4G EMM messages
            if (msg_type == 0x41 || msg_type == 0x45 || msg_type == 0x43 ||
                msg_type == 0x44 || msg_type == 0x46 || msg_type == 0x5D || msg_type == 0x5E) {
                nas_start = i;
                nas_length = (s1ap_len - i) > 64 ? 64 : (s1ap_len - i);
                LOG_DEBUG("4G EMM message (0x%02X) selected for conversion\n", msg_type);
                break;
            }
        }
    }

    const uint8_t *nas_source = NULL;
    size_t nas_source_len = 0;
    if (nas_ie_copy_len > 0) {
        nas_source = nas_ie_copy;
        nas_source_len = nas_ie_copy_len;
        nas_length = nas_ie_copy_len;
        LOG_DEBUG("Using NAS-PDU extracted via ASN.1 decode (len=%zu)\n", nas_source_len);
    } else if (nas_length > 0) {
        nas_source = s1ap_data + nas_start;
        nas_source_len = nas_length;
        LOG_DEBUG("Using NAS-PDU located via heuristic scan (offset=%zu, len=%zu)\n",
               nas_start, nas_length);
    }

    nas_length = nas_source_len;

    #define SET_BE32(BUF, IDX, V) do { \
        (BUF)[(IDX)+0] = (uint8_t)(((V) >> 24) & 0xFF); \
        (BUF)[(IDX)+1] = (uint8_t)(((V) >> 16) & 0xFF); \
        (BUF)[(IDX)+2] = (uint8_t)(((V) >> 8) & 0xFF); \
        (BUF)[(IDX)+3] = (uint8_t)((V) & 0xFF); \
    } while (0)

    ssize_t idx_len_outer = -1, idx_len_mid = -1, idx_len_iecontainer = -1;
    for (size_t i = 0; i + 3 < sizeof(initial_ue); ++i) {
        if (initial_ue[i] == 0x00 && initial_ue[i + 1] == 0x00 && initial_ue[i + 2] == 0x00) {
            if (initial_ue[i + 3] == 0x7C && idx_len_outer < 0) {
                idx_len_outer = (ssize_t)i;
            } else if (initial_ue[i + 3] == 0x74 && idx_len_mid < 0) {
                idx_len_mid = (ssize_t)i;
            } else if (initial_ue[i + 3] == 0x70 && idx_len_iecontainer < 0) {
                idx_len_iecontainer = (ssize_t)i;
            }
        }
    }
    ssize_t idx_nas_ie_len = -1, idx_nas_len = -1, idx_nas_payload = -1;
    for (size_t i = 0; i + 15 < sizeof(initial_ue); ++i) {
        if (initial_ue[i + 0] == 0x00 && initial_ue[i + 1] == 0x00 && initial_ue[i + 2] == 0x00 &&
            initial_ue[i + 3] == 0x26 && initial_ue[i + 4] == 0x00 && initial_ue[i + 5] == 0x00 &&
            initial_ue[i + 6] == 0x00 && initial_ue[i + 7] == 0x00 && initial_ue[i + 8] == 0x00 &&
            initial_ue[i + 9] == 0x00 && initial_ue[i + 10] == 0x00 && initial_ue[i + 11] == 0x20 &&
            initial_ue[i + 12] == 0x00 && initial_ue[i + 13] == 0x00 && initial_ue[i + 14] == 0x00 &&
            initial_ue[i + 15] == 0x1C) {
            idx_nas_ie_len = (ssize_t)(i + 8);
            idx_nas_len = (ssize_t)(i + 12);
            idx_nas_payload = (ssize_t)(i + 16);
            break;
        }
    }

    for (size_t i = 0; i + 19 < sizeof(initial_ue); ++i) {
        if (initial_ue[i + 0] == 0x00 && initial_ue[i + 1] == 0x00 && initial_ue[i + 2] == 0x00 &&
            initial_ue[i + 3] == 0x55 && initial_ue[i + 8] == 0x00 && initial_ue[i + 9] == 0x00 &&
            initial_ue[i + 10] == 0x00 && initial_ue[i + 11] == 0x08 && initial_ue[i + 12] == 0x00 &&
            initial_ue[i + 13] == 0x00 && initial_ue[i + 14] == 0x00 && initial_ue[i + 15] == 0x04) {
            idx_ranue_id = (ssize_t)(i + 16);
            break;
        }
    }

    if (idx_ranue_id >= 0) {
        SET_BE32(initial_ue, (size_t)idx_ranue_id, (uint32_t)enb_ue_s1ap_id);
        LOG_DEBUG("Patched template RAN-UE-NGAP-ID with eNB UE ID %ld at offset %zd\n",
               enb_ue_s1ap_id, idx_ranue_id);
    } else {
        LOG_WARN("Failed to locate RAN-UE-NGAP-ID field in template; continuing with default\n");
    }

    LOG_DEBUG("Template InitialUEMessage: nas_length=%zu, idx_nas_payload=%zd\n",
           nas_length, idx_nas_payload);
    LOG_DEBUG("Template search results: idx_len_outer=%zd, idx_len_mid=%zd, idx_len_iecontainer=%zd\n",
           idx_len_outer, idx_len_mid, idx_len_iecontainer);
    LOG_DEBUG("NAS template positions: idx_nas_ie_len=%zd, idx_nas_len=%zd, idx_nas_payload=%zd\n",
           idx_nas_ie_len, idx_nas_len, idx_nas_payload);
    LOG_DEBUG("Condition check: (nas_length > 0 && idx_nas_payload > 0) = (%s && %s) = %s\n",
           nas_length > 0 ? "true" : "false",
           idx_nas_payload > 0 ? "true" : "false",
           (nas_length > 0 && idx_nas_payload > 0) ? "true" : "false");

    if (nas_source && nas_length > 0 && idx_nas_payload > 0) {
        uint32_t new_nas_len = (uint32_t)nas_length;
        uint32_t old_nas_len = 28;
        int32_t delta = (int32_t)new_nas_len - (int32_t)old_nas_len;

        size_t head_len = (size_t)idx_nas_payload;
        memcpy(ngap_data, initial_ue, head_len);
        SET_BE32(ngap_data, (size_t)idx_nas_len, new_nas_len);
        SET_BE32(ngap_data, (size_t)idx_nas_ie_len, (uint32_t)(new_nas_len + 4));
        if (idx_len_outer >= 0) SET_BE32(ngap_data, (size_t)idx_len_outer, (uint32_t)(0x7C + delta));
        if (idx_len_mid >= 0) SET_BE32(ngap_data, (size_t)idx_len_mid, (uint32_t)(0x74 + delta));
        if (idx_len_iecontainer >= 0) SET_BE32(ngap_data, (size_t)idx_len_iecontainer, (uint32_t)(0x70 + delta));

        LOG_DEBUG("About to call NAS conversion for %zu bytes\n", nas_length);

        uint8_t converted_nas[256];
        memset(converted_nas, 0, sizeof(converted_nas)); // Initialize buffer to prevent garbage bytes
        size_t converted_nas_len = 0;
    if (convert_4g_nas_to_5g(NULL,
                 NULL,
                 (uint8_t *)nas_source,
                                 nas_length,
                                 converted_nas,
                                 &converted_nas_len) == 0) {
            LOG_INFO("4G->5G NAS-PDU conversion successful (4G:%zu bytes -> 5G:%zu bytes)\n",
                   nas_length, converted_nas_len);

            new_nas_len = (uint32_t)converted_nas_len;
            delta = (int32_t)new_nas_len - (int32_t)old_nas_len;
            SET_BE32(ngap_data, (size_t)idx_nas_len, new_nas_len);
            SET_BE32(ngap_data, (size_t)idx_nas_ie_len, (uint32_t)(new_nas_len + 4));
            if (idx_len_outer >= 0) SET_BE32(ngap_data, (size_t)idx_len_outer, (uint32_t)(0x7C + delta));
            if (idx_len_mid >= 0) SET_BE32(ngap_data, (size_t)idx_len_mid, (uint32_t)(0x74 + delta));
            if (idx_len_iecontainer >= 0) SET_BE32(ngap_data, (size_t)idx_len_iecontainer, (uint32_t)(0x70 + delta));

            memcpy(ngap_data + head_len, converted_nas, converted_nas_len);
            nas_length = converted_nas_len;

            // Cache the converted 5G Registration Request for piggybacked re-transmission
            // after Security Mode Complete (3GPP TS 24.501 § 5.5.1.2.4)
            // Note: We don't have ctx here, so we'll cache it in uplink_nas_transport where ctx is available
        } else {
            LOG_WARN("4G->5G NAS-PDU conversion failed, using original 4G NAS-PDU\n");

            memcpy(ngap_data + head_len, nas_source, nas_length);
        }

        size_t tail_src_offset = (size_t)idx_nas_payload + old_nas_len;
        size_t tail_dst_offset = head_len + nas_length;
        size_t tail_len = sizeof(initial_ue) - tail_src_offset;
        memcpy(ngap_data + tail_dst_offset, initial_ue + tail_src_offset, tail_len);
        *ngap_len = head_len + nas_length + tail_len;
        LOG_INFO("InitialUEMessage built with NAS-PDU from S1AP (len=%u, delta=%d)\n",
               new_nas_len, delta);

    } else {
        LOG_DEBUG("Taking ELSE path - attempting template with NAS replacement\n");
        LOG_DEBUG("nas_length=%zu, idx_nas_payload=%zd\n", nas_length, idx_nas_payload);

        memcpy(ngap_data, initial_ue, sizeof(initial_ue));
        *ngap_len = sizeof(initial_ue);

        if (nas_source && nas_length > 0) {
            LOG_INFO("Template NAS conversion attempt for detected 4G NAS-PDU (%zu bytes)\n",
                   nas_length);
            uint8_t converted_nas[256];
            size_t converted_nas_len = 0;
            if (convert_4g_nas_to_5g(NULL,
                                     NULL,
                                     (uint8_t *)nas_source,
                                     nas_length,
                                     converted_nas,
                                     &converted_nas_len) == 0) {
                LOG_INFO("Template 4G->5G NAS-PDU conversion successful (4G:%zu bytes -> 5G:%zu bytes)\n",
                       nas_length, converted_nas_len);

                const size_t template_nas_offset = 0x18;
                const size_t template_nas_max_len = 32;

                if (converted_nas_len <= template_nas_max_len &&
                    template_nas_offset + template_nas_max_len <= sizeof(initial_ue)) {
                    LOG_INFO("Replacing template NAS-PDU with converted 5G NAS at offset 0x%zx\n",
                           template_nas_offset);

                    ngap_data[template_nas_offset - 1] = (uint8_t)converted_nas_len;
                    memcpy(ngap_data + template_nas_offset, converted_nas, converted_nas_len);

                    if (converted_nas_len < template_nas_max_len) {
                        memset(ngap_data + template_nas_offset + converted_nas_len,
                               0,
                               template_nas_max_len - converted_nas_len);
                    }

                } else {
                    LOG_WARN("Converted NAS-PDU too large for template (%zu > %zu bytes)\n",
                           converted_nas_len, template_nas_max_len);
                }
            } else {
                LOG_WARN("Template 4G->5G NAS-PDU conversion failed\n");
            }

        } else {
            LOG_WARN("Could not locate NAS-PDU in S1AP; using original template NAS in NGAP InitialUEMessage\n");
        }

    }

    const char *env_mcc = getenv("S1N2_MCC");
    if (!env_mcc || !*env_mcc) env_mcc = getenv("MCC");
    if (!env_mcc || !*env_mcc) env_mcc = "001";

    const char *env_mnc = getenv("S1N2_MNC");
    if (!env_mnc || !*env_mnc) env_mnc = getenv("MNC");
    if (!env_mnc || !*env_mnc) env_mnc = "01";

    const char *env_tac = getenv("S1N2_TAC");
    if (!env_tac || !*env_tac) env_tac = getenv("TAC");
    if (!env_tac || !*env_tac) env_tac = "1";

    char mcc[4] = {'0','0','0','\0'};
    size_t mcc_len = strlen(env_mcc);
    if (mcc_len >= 3) {
        mcc[0] = env_mcc[mcc_len - 3];
        mcc[1] = env_mcc[mcc_len - 2];
        mcc[2] = env_mcc[mcc_len - 1];
    } else if (mcc_len == 2) {
        mcc[1] = env_mcc[0];
        mcc[2] = env_mcc[1];
    }

    char mnc[4] = {'0','0','0','\0'};
    size_t mnc_len = strlen(env_mnc);
    if (mnc_len >= 3) {
        mnc[0] = env_mnc[mnc_len - 3];
        mnc[1] = env_mnc[mnc_len - 2];
        mnc[2] = env_mnc[mnc_len - 1];
    } else if (mnc_len == 2) {
        mnc[1] = env_mnc[0];
        mnc[2] = env_mnc[1];
    }

    long tac = strtol(env_tac, NULL, 10);
    if (tac < 0 || tac > 0xFFFFFF) {
        tac = 1;
    }

    if (idx_ranue_id >= 0) {
        SET_BE32(ngap_data, (size_t)idx_ranue_id, (uint32_t)enb_ue_s1ap_id);
    }

    if (idx_nas_payload > 0 && nas_length > 0) {
        memcpy(ngap_data + (size_t)idx_nas_payload, nas_source, nas_length);
    }

    if (mcc_len > 0) {
        ngap_data[0x34] = (uint8_t)(((mcc[1] - '0') << 4) | (mcc[0] - '0'));
        ngap_data[0x35] = (uint8_t)(((mnc[0] - '0') << 4) | (mcc[2] - '0'));
        ngap_data[0x36] = (uint8_t)(((mnc[2] - '0') << 4) | (mnc[1] - '0'));
    }

    ngap_data[0x37] = (uint8_t)((tac >> 16) & 0xFF);
    ngap_data[0x38] = (uint8_t)((tac >> 8) & 0xFF);
    ngap_data[0x39] = (uint8_t)(tac & 0xFF);

    const char *env_name = getenv("S1N2_RAN_NAME");
    if (!env_name || !*env_name) env_name = "s1n2-gNB";
    LOG_INFO("InitialUEMessage conversion complete for eNB UE ID %ld (RAN name: %s)\n",
           enb_ue_s1ap_id, env_name);

    return 0;
}
