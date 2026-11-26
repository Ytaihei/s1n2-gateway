#include "s1n2_log.h"
/**
 * @file nas_transport_dl.c
 * @brief Downlink NAS Transport conversion
 *
 * S1AP DownlinkNASTransport -> NGAP (with 4G->5G NAS conversion)
 * NGAP DownlinkNASTransport -> S1AP (with 5G->4G NAS conversion)
 */
#include "internal/s1n2_converter_internal.h"
#include "security/security.h"

int s1n2_convert_downlink_nas_transport(s1n2_context_t *ctx,
                                       uint8_t *s1ap_data, size_t s1ap_len,
                                       uint8_t *ngap_data, size_t *ngap_len) {
    if (!s1ap_data || !ngap_data || !ngap_len || *ngap_len == 0) {
        return -1;
    }

    S1AP_S1AP_PDU_t *pdu = NULL;
    uint8_t *nas_original = NULL;
    int ret = -1;

    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                             (void **)&pdu, s1ap_data, s1ap_len);
    if (dr.code != RC_OK || !pdu || pdu->present != S1AP_S1AP_PDU_PR_initiatingMessage) {
        LOG_ERROR("Failed to decode S1AP DownlinkNASTransport (code=%d)\n", dr.code);

        goto cleanup;
    }

    S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    if (!init || init->value.present != S1AP_InitiatingMessage__value_PR_DownlinkNASTransport) {
        LOG_ERROR("S1AP message is not DownlinkNASTransport\n");

        goto cleanup;
    }

    long mme_ue_id = -1;
    long enb_ue_id = -1;
    const uint8_t *nas_buf = NULL;
    size_t nas_len = 0;

    S1AP_DownlinkNASTransport_t *msg = &init->value.choice.DownlinkNASTransport;
    for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
        S1AP_DownlinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie) {
            continue;
        }

        switch (ie->id) {
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                if (ie->value.present == S1AP_DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID) {
                    mme_ue_id = (long)ie->value.choice.MME_UE_S1AP_ID;
                }
                break;
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                if (ie->value.present == S1AP_DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID) {
                    enb_ue_id = (long)ie->value.choice.ENB_UE_S1AP_ID;
                }
                break;
            case S1AP_ProtocolIE_ID_id_NAS_PDU:
                if (ie->value.present == S1AP_DownlinkNASTransport_IEs__value_PR_NAS_PDU &&
                    ie->value.choice.NAS_PDU.buf && ie->value.choice.NAS_PDU.size > 0) {
                    nas_buf = (const uint8_t *)ie->value.choice.NAS_PDU.buf;
                    nas_len = ie->value.choice.NAS_PDU.size;
                }
                break;
            default:
                break;
        }
    }

    if (!nas_buf || nas_len == 0) {
        LOG_ERROR("S1AP DownlinkNASTransport missing NAS-PDU\n");

        goto cleanup;
    }

    nas_original = malloc(nas_len);
    if (!nas_original) {
        LOG_ERROR("Failed to allocate buffer for NAS-PDU copy (len=%zu)\n", nas_len);

        goto cleanup;
    }
    memcpy(nas_original, nas_buf, nas_len);

    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
    pdu = NULL;

    long ran_ue_id = -1;
    long amf_ue_id = -1;
    ue_id_mapping_t *ue_map = NULL;

    if (ctx) {
        if (enb_ue_id >= 0) {
            ue_map = s1n2_context_find_mapping_by_enb(ctx, enb_ue_id);
            if (!ue_map) {
                ue_map = s1n2_context_ensure_mapping_for_enb(ctx, enb_ue_id);
            }
        }
        if (!ue_map && mme_ue_id >= 0) {
            ue_map = s1n2_context_find_mapping_by_amf(ctx, mme_ue_id);
        }
        if (!ue_map && mme_ue_id >= 0) {
            long preferred_ran = (enb_ue_id >= 0) ? enb_ue_id : -1;
            long new_ran_id = s1n2_context_generate_ran_ue_ngap_id(ctx, preferred_ran);
            long new_enb_id = (enb_ue_id >= 0) ? enb_ue_id : new_ran_id;
            ue_map = s1n2_context_create_mapping(ctx, new_ran_id, mme_ue_id, new_enb_id, mme_ue_id);
            if (ue_map) {
                LOG_INFO("Created UE mapping for DownlinkNASTransport (RAN=%ld, AMF=%ld)\n",
                       ue_map->ran_ue_ngap_id, ue_map->amf_ue_ngap_id);

            }
        }

        if (ue_map) {
            if (enb_ue_id >= 0) {
                ue_map->enb_ue_s1ap_id = enb_ue_id;
            }
            if (mme_ue_id >= 0) {
                ue_map->mme_ue_s1ap_id = mme_ue_id;
                ue_map->amf_ue_ngap_id = mme_ue_id;
            }
            if (ue_map->ran_ue_ngap_id <= 0) {
                ue_map->ran_ue_ngap_id = (enb_ue_id >= 0) ? enb_ue_id : ctx->next_ran_ue_ngap_id++;
            }
            ran_ue_id = ue_map->ran_ue_ngap_id;
            if (ue_map->amf_ue_ngap_id > 0) {
                amf_ue_id = ue_map->amf_ue_ngap_id;
            }
            ue_map->last_update = time(NULL);
        }
    }

    if (amf_ue_id < 0 && mme_ue_id >= 0) {
        amf_ue_id = mme_ue_id;
    }
    if (ran_ue_id < 0 && enb_ue_id >= 0) {
        ran_ue_id = enb_ue_id;
    }

    if (ran_ue_id < 0) {
        ran_ue_id = 1;
    }
    if (amf_ue_id < 0) {
        amf_ue_id = 1;
    }

    LOG_DEBUG("DownlinkNASTransport IDs: ENB=%ld, MME=%ld -> RAN=%ld, AMF=%ld\n",
           enb_ue_id, mme_ue_id, ran_ue_id, amf_ue_id);

    uint8_t nas_5g_buf[512];
    size_t nas_5g_len = sizeof(nas_5g_buf);
    const uint8_t *final_nas = nas_original;
    size_t final_nas_len = nas_len;

    // ============================================================
    // TAU Accept Detection (Downlink from MME)
    // ============================================================
    if (ue_map && nas_len >= 2) {
        uint8_t nas_msg_type = nas_original[1];
        LOG_DEBUG("[TAU-CHECK-DL] NAS Message Type: 0x%02X\n", nas_msg_type);

        if (nas_msg_type == 0x49) {
            LOG_INFO("========== TAU ACCEPT DETECTED (DL) ==========\n");
            LOG_INFO("UE mapping %p completed TAU locally (ENB=%ld, MME=%ld)\n",
                   (void *)ue_map, enb_ue_id, mme_ue_id);

            s1n2_context_mark_tau_complete(ue_map);
        }
    }

    if (nas_len > sizeof(nas_5g_buf)) {
        LOG_WARN("NAS-PDU length %zu exceeds conversion buffer (%zu), forwarding original NAS\n",
               nas_len, sizeof(nas_5g_buf));

    } else {
        if (convert_4g_nas_to_5g(ctx, ue_map, nas_original, nas_len, nas_5g_buf, &nas_5g_len) == 0) {
            final_nas = nas_5g_buf;
            final_nas_len = nas_5g_len;
            LOG_INFO("4G->5G NAS conversion succeeded (4G=%zu bytes -> 5G=%zu bytes)\n",
                   nas_len, nas_5g_len);
        } else {
            LOG_WARN("4G->5G NAS conversion failed, forwarding original NAS\n");
        }

    }

    size_t out_len = *ngap_len;
    if (build_ngap_downlink_nas(ngap_data, &out_len, amf_ue_id, ran_ue_id,
                                 final_nas, final_nas_len) != 0) {
        LOG_ERROR("Failed to build NGAP DownlinkNASTransport\n");

        goto cleanup;
    }

    *ngap_len = out_len;
    LOG_INFO("Converted S1AP DownlinkNASTransport to NGAP (AMF-UE=%ld, RAN-UE=%ld, NAS=%zu bytes)\n",
           amf_ue_id, ran_ue_id, final_nas_len);

    ret = 0;

cleanup:
    if (pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
    }
    if (nas_original) {
        free(nas_original);
    }
    return ret;
}

/* build_ngap_* / build_s1ap_downlink_nas / cause helpers – moved to src/cplane/s1n2_builders.c */
