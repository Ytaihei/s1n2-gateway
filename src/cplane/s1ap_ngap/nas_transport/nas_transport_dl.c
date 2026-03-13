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
        printf("[ERROR] Failed to decode S1AP DownlinkNASTransport (code=%d)\n", dr.code);
        fflush(stdout);
        goto cleanup;
    }

    S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    if (!init || init->value.present != S1AP_InitiatingMessage__value_PR_DownlinkNASTransport) {
        printf("[ERROR] S1AP message is not DownlinkNASTransport\n");
        fflush(stdout);
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
        printf("[ERROR] S1AP DownlinkNASTransport missing NAS-PDU\n");
        fflush(stdout);
        goto cleanup;
    }

    nas_original = malloc(nas_len);
    if (!nas_original) {
        printf("[ERROR] Failed to allocate buffer for NAS-PDU copy (len=%zu)\n", nas_len);
        fflush(stdout);
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
                printf("[INFO] Created UE mapping for DownlinkNASTransport (RAN=%ld, AMF=%ld)\n",
                       ue_map->ran_ue_ngap_id, ue_map->amf_ue_ngap_id);
                fflush(stdout);
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

    printf("[DEBUG] DownlinkNASTransport IDs: ENB=%ld, MME=%ld -> RAN=%ld, AMF=%ld\n",
           enb_ue_id, mme_ue_id, ran_ue_id, amf_ue_id);
    fflush(stdout);

    uint8_t nas_5g_buf[512];
    size_t nas_5g_len = sizeof(nas_5g_buf);
    const uint8_t *final_nas = nas_original;
    size_t final_nas_len = nas_len;

    // ============================================================
    // TAU Accept Detection (Downlink from MME)
    // ============================================================
    if (ue_map && nas_len >= 2) {
        uint8_t nas_msg_type = nas_original[1];
        printf("[DEBUG] [TAU-CHECK-DL] NAS Message Type: 0x%02X\n", nas_msg_type);

        if (nas_msg_type == 0x49) {
            printf("[INFO] ========== TAU ACCEPT DETECTED (DL) ==========\n");
            printf("[INFO] UE mapping %p completed TAU locally (ENB=%ld, MME=%ld)\n",
                   (void *)ue_map, enb_ue_id, mme_ue_id);
            fflush(stdout);
            s1n2_context_mark_tau_complete(ue_map);
        }
    }

    if (nas_len > sizeof(nas_5g_buf)) {
        printf("[WARN] NAS-PDU length %zu exceeds conversion buffer (%zu), forwarding original NAS\n",
               nas_len, sizeof(nas_5g_buf));
        fflush(stdout);
    } else {
        if (convert_4g_nas_to_5g(ctx, ue_map, nas_original, nas_len, nas_5g_buf, &nas_5g_len) == 0) {
            final_nas = nas_5g_buf;
            final_nas_len = nas_5g_len;
            printf("[INFO] 4G->5G NAS conversion succeeded (4G=%zu bytes -> 5G=%zu bytes)\n",
                   nas_len, nas_5g_len);
        } else {
            printf("[WARN] 4G->5G NAS conversion failed, forwarding original NAS\n");
        }
        fflush(stdout);
    }

    size_t out_len = *ngap_len;
    if (build_ngap_downlink_nas(ngap_data, &out_len, amf_ue_id, ran_ue_id,
                                 final_nas, final_nas_len) != 0) {
        printf("[ERROR] Failed to build NGAP DownlinkNASTransport\n");
        fflush(stdout);
        goto cleanup;
    }

    *ngap_len = out_len;
    printf("[INFO] Converted S1AP DownlinkNASTransport to NGAP (AMF-UE=%ld, RAN-UE=%ld, NAS=%zu bytes)\n",
           amf_ue_id, ran_ue_id, final_nas_len);
    fflush(stdout);

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

int s1n2_convert_ngap_downlink_nas_transport(s1n2_context_t *ctx,
                                             uint8_t *ngap_data, size_t ngap_len,
                                             uint8_t *s1ap_data, size_t *s1ap_len) {
    if (!ngap_data || !s1ap_data || !s1ap_len || *s1ap_len == 0)
        return -1;

    NGAP_NGAP_PDU_t *pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_NGAP_NGAP_PDU, (void**)&pdu, ngap_data, ngap_len);
    if (dr.code != RC_OK || !pdu || pdu->present != NGAP_NGAP_PDU_PR_initiatingMessage) {
        printf("[ERROR] Failed to decode NGAP DownlinkNASTransport (code=%d)\n", dr.code);
        fflush(stdout);
        if (pdu) ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        return -1;
    }

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    if (!init || init->procedureCode != NGAP_ProcedureCode_id_DownlinkNASTransport ||
        init->value.present != NGAP_InitiatingMessage__value_PR_DownlinkNASTransport) {
        printf("[ERROR] NGAP message is not DownlinkNASTransport (proc=%ld)\n",
               init ? (long)init->procedureCode : -1);
        fflush(stdout);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        return -1;
    }

    long amf_ue_id = -1;
    long ran_ue_id = -1;
    const uint8_t *nas_buf = NULL;
    size_t nas_len = 0;

    NGAP_DownlinkNASTransport_t *msg = &init->value.choice.DownlinkNASTransport;
    for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
        NGAP_DownlinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie) continue;

        switch (ie->id) {
            case NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID:
                if (ie->value.present == NGAP_DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID) {
                    if (asn_INTEGER2long(&ie->value.choice.AMF_UE_NGAP_ID, &amf_ue_id) != 0)
                        printf("[WARN] Failed to decode AMF-UE NGAP ID\n");
                }
                break;
            case NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID:
                if (ie->value.present == NGAP_DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID)
                    ran_ue_id = ie->value.choice.RAN_UE_NGAP_ID;
                break;
            case NGAP_ProtocolIE_ID_id_NAS_PDU:
                if (ie->value.present == NGAP_DownlinkNASTransport_IEs__value_PR_NAS_PDU &&
                    ie->value.choice.NAS_PDU.buf && ie->value.choice.NAS_PDU.size > 0) {
                    nas_buf = ie->value.choice.NAS_PDU.buf;
                    nas_len = ie->value.choice.NAS_PDU.size;
                }
                break;
            default:
                break;
        }
    }

    if (!nas_buf || nas_len == 0) {
        printf("[ERROR] NGAP DownlinkNASTransport missing NAS-PDU\n");
        fflush(stdout);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        return -1;
    }

    long mme_ue_id = (amf_ue_id >= 0) ? amf_ue_id : 1;
    long enb_ue_id = (ran_ue_id >= 0) ? ran_ue_id : 1;
    ue_id_mapping_t *ue_map = NULL;

    if (ctx) {
        if (ran_ue_id >= 0) {
            ue_map = s1n2_context_find_mapping_by_ran(ctx, ran_ue_id);
        }
        if (!ue_map && amf_ue_id >= 0) {
            ue_map = s1n2_context_find_mapping_by_amf(ctx, amf_ue_id);
        }

        if (ue_map) {
            if (ue_map->enb_ue_s1ap_id > 0) {
                enb_ue_id = ue_map->enb_ue_s1ap_id;
            }
            if (ue_map->mme_ue_s1ap_id > 0) {
                mme_ue_id = ue_map->mme_ue_s1ap_id;
            }
            if (amf_ue_id >= 0) {
                ue_map->amf_ue_ngap_id = amf_ue_id;
                ue_map->mme_ue_s1ap_id = amf_ue_id;
            }
            if (ran_ue_id >= 0) {
                ue_map->ran_ue_ngap_id = ran_ue_id;
            }
            printf("[DEBUG] UE mapping applied for DownlinkNASTransport (RAN=%ld -> ENB=%ld, MME=%ld)\n",
                   ran_ue_id, enb_ue_id, mme_ue_id);
            fflush(stdout);
        } else {
            printf("[WARN] UE mapping not found for DownlinkNASTransport (RAN=%ld, AMF=%ld)\n",
                   ran_ue_id, amf_ue_id);
            fflush(stdout);
        }
    }

    // Try to extract RAND/AUTN from 5G Authentication Request and cache it
    if (ctx && nas_buf && nas_len >= 3) {
        uint8_t rand[16] = {0};
        uint8_t autn[16] = {0};
        uint8_t sqn_xor_ak[6] = {0};

        // Find or create UE mapping first for ABBA caching
        ue_id_mapping_t *cache_map = ue_map;
        if (!cache_map && ran_ue_id >= 0) {
            cache_map = s1n2_context_find_mapping_by_ran(ctx, ran_ue_id);
        }
        if (!cache_map && amf_ue_id >= 0) {
            cache_map = s1n2_context_find_mapping_by_amf(ctx, amf_ue_id);
        }
        if (!cache_map && (ran_ue_id >= 0 || amf_ue_id >= 0)) {
            long new_ran_id = (ran_ue_id >= 0)
                                 ? ran_ue_id
                                 : s1n2_context_generate_ran_ue_ngap_id(ctx, -1);
            long new_amf_id = (amf_ue_id >= 0) ? amf_ue_id : new_ran_id;
            long new_enb_id = (enb_ue_id >= 0) ? enb_ue_id : new_ran_id;
            long new_mme_id = (mme_ue_id >= 0) ? mme_ue_id : new_amf_id;
            cache_map = s1n2_context_create_mapping(ctx, new_ran_id, new_amf_id,
                                                    new_enb_id, new_mme_id);
            if (cache_map) {
                printf("[INFO] Created new UE mapping for Authentication Request (RAN=%ld, AMF=%ld)\n",
                       ran_ue_id, amf_ue_id);
            }
        }

        // Extract RAND/AUTN/ABBA and cache them
        if (s1n2_extract_rand_autn_from_5g_auth_request(nas_buf, nas_len, rand, autn, sqn_xor_ak, cache_map) == 0) {
            if (cache_map) {
                memcpy(cache_map->rand, rand, 16);
                cache_map->rand_cached = true;
                cache_map->rand_timestamp = time(NULL);
                memcpy(cache_map->autn, autn, 16);
                memcpy(cache_map->sqn_xor_ak, sqn_xor_ak, 6);
                cache_map->autn_cached = true;

                // CRITICAL FIX 2025-11-16: Log SQN^AK extraction for verification
                printf("[SUCCESS] [SQN-FIX] Extracted and cached SQN^AK from 5G Auth Request\n");
                printf("[SUCCESS] [SQN-FIX]   SQN^AK: ");
                for (int i = 0; i < 6; i++) printf("%02X", sqn_xor_ak[i]);
                printf("\n");
                printf("[SUCCESS] [SQN-FIX]   This will be used for KASME derivation (prevents Sync Failure)\n");

                printf("[SUCCESS] Cached RAND/AUTN/ABBA for UE (RAN-UE-ID=%ld, AMF-UE-ID=%ld)\n",
                       ran_ue_id, amf_ue_id);

                if (cache_map->imsi[0] == '\0') {
                    printf("[WARN] IMSI not cached for UE, authentication may fail\n");
                    printf("[WARN] IMSI should have been extracted from Registration Request\n");
                } else {
                    printf("[INFO] Using cached IMSI for authentication: %s\n", cache_map->imsi);
                }
                if (!cache_map->has_nas_keys && cache_map->imsi[0] != '\0') {
                    if (s1n2_try_derive_4g_nas_keys(ctx, cache_map) == 0) {
                        printf("[INFO] [NAS-KEY] Derived NAS keys immediately after Auth Request\n");
                        fflush(stdout);
                    }
                }
                ue_map = cache_map;
            } else {
                printf("[WARN] Could not find or create UE mapping to cache RAND\n");
            }
        }
    }

    const uint8_t *downlink_nas = nas_buf;
    size_t downlink_nas_len = nas_len;
    uint8_t nas_4g_buf[256];
    size_t nas_4g_len = sizeof(nas_4g_buf);
    bool nas_converted = false;
    s1n2_security_mode_info_t sm_info;
    memset(&sm_info, 0, sizeof(sm_info));

    if (nas_len > sizeof(nas_4g_buf)) {
        printf("[WARN] NAS-PDU length %zu exceeds 4G buffer size, forwarding original 5G NAS\n", nas_len);
    } else {
    if (convert_5g_nas_to_4g(nas_buf, nas_len, nas_4g_buf, &nas_4g_len, &sm_info, ue_map) == 0) {
            downlink_nas = nas_4g_buf;
            downlink_nas_len = nas_4g_len;
            nas_converted = true;
            printf("[INFO] DownlinkNASTransport: 5G NAS converted to 4G NAS (5G len=%zu, 4G len=%zu)\n",
                   nas_len, nas_4g_len);
        } else {
            printf("[WARN] DownlinkNASTransport: 5G->4G NAS conversion failed, forwarding original NAS\n");
        }
    }

    if (nas_converted && ctx && sm_info.has_security_mode) {
        ue_id_mapping_t *security_map = ue_map;
        if (!security_map && ran_ue_id >= 0) {
            security_map = s1n2_context_find_mapping_by_ran(ctx, ran_ue_id);
        }
        if (!security_map && amf_ue_id >= 0) {
            security_map = s1n2_context_find_mapping_by_amf(ctx, amf_ue_id);
        }
        if (!security_map && (ran_ue_id >= 0 || amf_ue_id >= 0)) {
            long new_ran_id = (ran_ue_id >= 0)
                                 ? ran_ue_id
                                 : s1n2_context_generate_ran_ue_ngap_id(ctx, -1);
            long new_amf_id = (amf_ue_id >= 0) ? amf_ue_id : new_ran_id;
            long new_enb_id = (enb_ue_id >= 0) ? enb_ue_id : new_ran_id;
            long new_mme_id = (mme_ue_id >= 0) ? mme_ue_id : new_amf_id;
            security_map = s1n2_context_create_mapping(ctx, new_ran_id, new_amf_id,
                                                       new_enb_id, new_mme_id);
        }

        if (security_map) {
            if (security_map->enb_ue_s1ap_id <= 0 && enb_ue_id >= 0) {
                security_map->enb_ue_s1ap_id = enb_ue_id;
            }
            if (security_map->mme_ue_s1ap_id <= 0 && mme_ue_id >= 0) {
                security_map->mme_ue_s1ap_id = mme_ue_id;
            }
            security_map->has_selected_alg_5g = sm_info.has_selected_alg_5g;
            if (sm_info.has_selected_alg_5g) {
                security_map->selected_alg_5g = sm_info.selected_alg_5g;
            }
            security_map->selected_nas_security_alg = sm_info.selected_alg_4g;
            security_map->last_ngksi = sm_info.ngksi;
            security_map->last_ngksi_octet = sm_info.ngksi_octet;
            security_map->has_last_ngksi_5g = true;
            security_map->last_ngksi_5g = sm_info.ngksi & 0x07;
            security_map->last_ngksi_tsc_5g = (sm_info.ngksi_octet >> 3) & 0x01;
            security_map->has_security_mode = true;
            security_map->has_cached_ue_security_cap = sm_info.has_ue_security_cap;
            if (sm_info.has_ue_security_cap && sm_info.ue_security_cap_len > 0) {
                size_t cap_len = sm_info.ue_security_cap_len;
                if (cap_len > sizeof(security_map->cached_ue_security_cap)) {
                    cap_len = sizeof(security_map->cached_ue_security_cap);
                }
                memcpy(security_map->cached_ue_security_cap,
                       sm_info.ue_security_cap,
                       cap_len);
                if (cap_len < sizeof(security_map->cached_ue_security_cap)) {
                    memset(security_map->cached_ue_security_cap + cap_len,
                           0,
                           sizeof(security_map->cached_ue_security_cap) - cap_len);
                }
                security_map->cached_ue_security_cap_len = (uint8_t)cap_len;
            } else {
                memset(security_map->cached_ue_security_cap, 0,
                       sizeof(security_map->cached_ue_security_cap));
                security_map->cached_ue_security_cap_len = 0;
            }
		security_map->has_cached_ue_security_cap_5g = sm_info.has_ue_security_cap_5g;
		if (sm_info.has_ue_security_cap_5g && sm_info.ue_security_cap_5g_len > 0) {
			size_t cap5_len = sm_info.ue_security_cap_5g_len;
			if (cap5_len > sizeof(security_map->cached_ue_security_cap_5g)) {
				cap5_len = sizeof(security_map->cached_ue_security_cap_5g);
			}
			memcpy(security_map->cached_ue_security_cap_5g,
			       sm_info.ue_security_cap_5g,
			       cap5_len);
			if (cap5_len < sizeof(security_map->cached_ue_security_cap_5g)) {
				memset(security_map->cached_ue_security_cap_5g + cap5_len,
				       0,
				       sizeof(security_map->cached_ue_security_cap_5g) - cap5_len);
			}
			security_map->cached_ue_security_cap_5g_len = (uint8_t)cap5_len;
		} else {
			memset(security_map->cached_ue_security_cap_5g, 0,
			       sizeof(security_map->cached_ue_security_cap_5g));
			security_map->cached_ue_security_cap_5g_len = 0;
		}
            security_map->imeisv_requested = sm_info.imeisv_requested;
            security_map->additional_security_info_present = sm_info.additional_security_info_present;
            security_map->additional_security_info = sm_info.additional_security_info;
         security_map->last_update = time(NULL);

         // CRITICAL: Reset NAS UL COUNT to 0 when receiving Security Mode Command
         // AMF sends Security Mode Command with security_header_type=0x03 (new context)
         // which means COUNT must be reset to 0 for subsequent messages
         printf("[DEBUG] [COUNT-RESET] Before reset: nas_ul_count_5g=0x%08X (RAN=%ld, AMF=%ld)\n",
             security_map->nas_ul_count_5g, ran_ue_id, amf_ue_id);
         security_map->nas_ul_count_5g = 0;
         printf("[INFO] [COUNT-RESET] Reset NAS UL COUNT to 0 for new security context (RAN=%ld, AMF=%ld)\n",
             ran_ue_id, amf_ue_id);

         printf("[INFO] Cached Security Mode info for UE (RAN=%ld, AMF=%ld) - alg=0x%02X, ngKSI=0x%02X\n",
             ran_ue_id, amf_ue_id, sm_info.selected_alg_4g, sm_info.ngksi);
        } else {
            printf("[WARN] Failed to cache security mode info (no UE mapping)\n");
        }
    }

    // If this downlink NAS is a 4G Attach Accept, prefer sending S1AP InitialContextSetupRequest
    // with NAS-PDU embedded in the E-RAB item so that eNB proceeds to bearer setup and UE can send Attach Complete.
    bool is_attach_accept = false;
    size_t attach_plain_off = 0; // offset to the start of plain EPS NAS (0x07 0x42 ...)
    if (nas_converted && downlink_nas_len >= 2) {
        // Case 1: plain EPS NAS (no security header)
        if (downlink_nas[0] == 0x07 && downlink_nas[1] == 0x42) {
            is_attach_accept = true;
            attach_plain_off = 0;
            printf("[DEBUG] [ICS-TRIGGER] Detected plain Attach Accept (0x07 0x42)\n");
        }
        // Case 2: integrity-only protected EPS NAS (0x17).
        // Format: [SecHdr(1)] [MAC(4)] [SEQ(1)] [Plain EPS NAS starting at 0x07 0x42 ...]
        else if (downlink_nas_len >= 8 && downlink_nas[0] == 0x17) {
            if (downlink_nas[6] == 0x07 && downlink_nas[7] == 0x42) {
                is_attach_accept = true;
                attach_plain_off = 6; // skip MAC(4) + SEQ(1) plus 1-byte sec hdr
                printf("[DEBUG] [ICS-TRIGGER] Detected integrity-protected Attach Accept (0x17, plain at offset 6)\n");
            }
        }
        // Case 3: integrity + ciphering protected EPS NAS (0x27).
        // Format: [SecHdr(1)] [MAC(4)] [SEQ(1)] [Encrypted payload with 0x07 0x42 inside]
        // We cannot inspect encrypted payload, so use length heuristic
        // Typical Attach Accept with ESM container: 40-80 bytes
        else if (downlink_nas_len >= 7 && downlink_nas[0] == 0x27) {
            if (downlink_nas_len >= 40 && downlink_nas_len <= 80) {
                is_attach_accept = true;
                attach_plain_off = 6; // plain starts after header, but it's encrypted
                printf("[DEBUG] [ICS-TRIGGER] Detected encrypted Attach Accept (0x27, len=%zu)\n", downlink_nas_len);
            }
        }
    }
    if (is_attach_accept) { // 0x42 = Attach Accept
        // Check if ICS has already been sent for this UE to prevent duplicate ICS (eNB rejects duplicate ICS)
        ue_id_mapping_t *ue_map = s1n2_context_find_mapping_by_enb(ctx, enb_ue_id);
        if (ue_map && ue_map->ics_sent) {
            time_t now = time(NULL);
            double elapsed = difftime(now, ue_map->ics_sent_time);
            if (elapsed < 10.0) {  // Skip if ICS was sent within last 10 seconds
                printf("[INFO] [ICS] Already sent InitialContextSetup for UE (ENB=%ld) %.1f seconds ago, skipping duplicate\n",
                       enb_ue_id, elapsed);
                printf("[INFO] Sending DownlinkNASTransport instead\n");
                // Fall through to send DownlinkNASTransport instead
                goto send_downlink_nas_transport;
            } else {
                // More than 10 seconds elapsed, allow retry (UE may have detached and re-attached)
                printf("[WARN] [ICS] Allowing ICS retry after %.1f seconds (ENB=%ld)\n", elapsed, enb_ue_id);
            }
        } else if (ue_map && ue_map->ics_completed) {
            // ICS already completed, don't re-send; forward as DownlinkNAS
            printf("[INFO] [ICS] Already completed for UE (ENB=%ld), forwarding as DownlinkNAS\n", enb_ue_id);
            goto send_downlink_nas_transport;
        } else if (ue_map && ue_map->ics_failed) {
            // Previous attempt failed; allow retry but consider tweaking EBI to avoid duplicate errors
            printf("[WARN] [ICS] Previous ICS failed for UE (ENB=%ld); will retry with adjusted parameters if needed\n", enb_ue_id);
        }

        uint32_t s1u_ip_be = 0;
        uint32_t s1u_teid_be = 0;
        uint8_t  e_rab_id = 5;
        s1n2_uplane_select_s1u_endpoint(ctx, ue_map, &s1u_ip_be, &s1u_teid_be, &e_rab_id);

        // If last attempt failed with duplicate E-RAB ID or we see quick retries, try alternate EBI (6..15)
        if (ue_map && ue_map->ics_failed) {
            uint8_t alt_ebi = (uint8_t)(5 + (ue_map->ics_attempts % 10));
            if (alt_ebi >= 6 && alt_ebi <= 15) {
                printf("[WARN] [ICS] Adjusting E-RAB ID from %u to %u to avoid duplicate instances\n", e_rab_id, alt_ebi);
                e_rab_id = alt_ebi;
            }
        }

        size_t ics_len = *s1ap_len;
        // IMPORTANT: For ICS NAS-PDU, embed the NAS as-is. If integrity/ciphering header (0x1x/0x2x/0x3x/0x4x)
        // is present, keep it (UE expects integrity-protected NAS after SMC). Do NOT strip to plain.
        const uint8_t *ics_nas_pdu = downlink_nas;
        size_t ics_nas_len = downlink_nas_len;
        if (attach_plain_off != 0) {
            // We detected an integrity-wrapped Attach Accept (plain starts at offset attach_plain_off).
            // Keep the protection and embed the full NAS (starting at sec header).
            printf("[INFO] [ICS] Detected integrity-wrapped Attach Accept; embedding protected NAS as-is (len=%zu) into ICS\n",
                   ics_nas_len);
        } else {
            printf("[INFO] [ICS] Detected plain Attach Accept; embedding as-is (len=%zu) into ICS\n", ics_nas_len);
        }
        // 先頭ヘッダのダンプ（保護有無の確認と境界チェック用）
        {
            size_t dump = 0;
            printf("[TRACE] [ICS] NAS-PDU head: ");
            for (; dump < 24 && dump < ics_nas_len; ++dump) printf("%02X ", ics_nas_pdu[dump]);
            if (ics_nas_len > dump) printf("...");
            printf("\n");
            // Fingerprints and inner AA sanity
            size_t inner_off = (attach_plain_off != 0) ? attach_plain_off : 0;
            if (ics_nas_len > inner_off) {
                uint32_t crc_full = s1n2_crc32(ics_nas_pdu, ics_nas_len);
                uint32_t crc_inner = s1n2_crc32(ics_nas_pdu + inner_off, ics_nas_len - inner_off);
                printf("[TRACE] [ICS] NAS-PDU CRC32 full=0x%08X, inner@%zu=0x%08X (len=%zu)\n",
                       crc_full, inner_off, crc_inner, ics_nas_len - inner_off);
                if (ics_nas_len - inner_off >= 5) {
                    const uint8_t *p = ics_nas_pdu + inner_off;
                    // Expect 07 42 01 5A xx for AA with T3412 TV
                    printf("[TRACE] [ICS] inner-AA octets: %02X %02X %02X %02X %02X\n",
                           p[0], p[1], p[2], p[3], p[4]);
                    if (p[0]==0x07 && p[1]==0x42) {
                        if (p[3]==0x5A) {
                            uint8_t v = p[4];
                            uint8_t unit = (uint8_t)((v & 0xE0) >> 5);
                            uint8_t val = (uint8_t)(v & 0x1F);
                            int approx_min = -1;
                            if (unit==1) approx_min = val;
                            else if (unit==2) approx_min = val*6;
                            else if (unit==0) {
                                printf("[TRACE] [ICS] inner T3412: unit=2sec, value=%u (~%u sec)\n", val, (unsigned)(val*2));
                            }
                            if (approx_min >= 0) {
                                printf("[TRACE] [ICS] inner T3412: IEI=0x5A, value=0x%02X (unit=%u, ~%d min)\n", v, unit, approx_min);
                            } else if (unit!=0) {
                                printf("[TRACE] [ICS] inner T3412: IEI=0x5A, value=0x%02X (unit=%u)\n", v, unit);
                            }
                        } else {
                            printf("[WARN] [ICS] inner-AA T3412 IEI unexpected: got 0x%02X (expected 0x5A)\n", p[3]);
                        }
                    }
                }
            }
        }

        // NOTE: Do NOT send NGAP PDUSessionResourceSetupRequest to AMF here!
        // AMF does not have SMF context yet and will reject with "Cannot find PDU Session ID".
        // Proper 5G flow: AMF contacts SMF first, then AMF sends PDUSessionResourceSetupRequest to RAN.
        // For now, skip PDU Session setup entirely and let AMF/SMF handle it separately.
#if 0
        // Send NGAP PDUSessionResourceSetupRequest to AMF BEFORE creating S1AP ICS Request
        // This pre-registers the PDU Session ID with AMF so it won't send ErrorIndication
        {
            uint8_t pdu_session_id = e_rab_id;  // Use E-RAB ID as PDU Session ID
            uint8_t qci = 9;  // Default QCI for internet

            printf("[INFO] [DLNAS] Sending NGAP PDUSessionResourceSetupRequest to AMF before S1AP ICS Request\n");
            printf("[INFO] [DLNAS]   PDU Session ID=%u, QCI/QFI=%u, UPF IP=%s, TEID=0x%08x\n",
                   pdu_session_id, qci,
                   inet_ntoa(*(struct in_addr *)&s1u_ip_be),
                   ntohl(s1u_teid_be));
            fflush(stdout);

            uint8_t ngap_setup_req[512];
            size_t ngap_setup_req_len = sizeof(ngap_setup_req);

            if (build_ngap_pdu_session_setup_request(ngap_setup_req, &ngap_setup_req_len,
                                                    mme_ue_id, enb_ue_id,
                                                    pdu_session_id, qci,
                                                    s1u_ip_be, s1u_teid_be) == 0 &&
                ngap_setup_req_len > 0) {
                ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_setup_req, (size_t)ngap_setup_req_len,
                                            NULL, 0, htonl(60), 0, 0, 0, 0);
                if (sent == (ssize_t)ngap_setup_req_len) {
                    printf("[INFO] [DLNAS] Sent NGAP PDUSessionResourceSetupRequest to AMF (%zd bytes)\n", sent);
                    fflush(stdout);
                } else {
                    printf("[ERROR] [DLNAS] Failed to send NGAP PDUSessionResourceSetupRequest (ret=%zd, errno=%d)\n",
                           sent, errno);
                    fflush(stdout);
                }
            } else {
                printf("[WARN] [DLNAS] Skipping NGAP PDUSessionResourceSetupRequest (placeholder not implemented)\n");
                fflush(stdout);
            }
        }
#endif

        int rc_ics = build_s1ap_initial_context_setup_request(s1ap_data, &ics_len,
                                                              mme_ue_id, enb_ue_id,
                                                              ics_nas_pdu, ics_nas_len,
                                                              e_rab_id, s1u_ip_be, s1u_teid_be,
                                                              (ue_map && ue_map->has_kenb) ? ue_map->kenb : NULL);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        if (rc_ics != 0) {
            printf("[ERROR] Failed to build S1AP InitialContextSetupRequest (from Attach Accept)\n");
            fflush(stdout);
            return -1;
        }
        *s1ap_len = ics_len;

        // Log KeNB status for debugging
        if (ue_map) {
            if (ue_map->has_kenb) {
                printf("[INFO] ICS Request built with derived KeNB (COUNT=0x%08X)\n", ue_map->kenb_ul_count);
            } else {
                printf("[WARN] ICS Request built without KeNB (derivation failed or not yet performed)\n");
            }
        }

        // Mark ICS as sent for this UE to prevent duplicates (in-flight)
        if (ue_map) {
            ue_map->ics_sent = true;
            ue_map->ics_sent_time = time(NULL);
            ue_map->ics_e_rab_id = e_rab_id;
            ue_map->ics_failed = false; // reset failure flag on new attempt
            printf("[INFO] [ICS] Marked ICS sent for UE (ENB=%ld, EBI=%u)\n", enb_ue_id, e_rab_id);

            // Store E-RAB information for later PDU Session establishment
            ue_map->has_pending_pdu_session = true;
            ue_map->pdu_session_id = e_rab_id;
            ue_map->qci = 9;  // Default QCI for internet
            ue_map->qfi = 9;  // Map to 5QI 9

            // Get APN from environment variable or use default
            const char *apn = getenv("S1N2_APN");
            if (!apn || !*apn) apn = getenv("APN");
            if (!apn || !*apn) apn = "internet";
            strncpy(ue_map->apn, apn, sizeof(ue_map->apn) - 1);
            ue_map->apn[sizeof(ue_map->apn) - 1] = '\0';

            printf("[INFO] [ICS] Stored E-RAB info for PDU Session: ID=%u, QCI=%u, QFI=%u, APN=%s\n",
                   ue_map->pdu_session_id, ue_map->qci, ue_map->qfi, ue_map->apn);
        }

        printf("[SUCCESS] Bridged 5G Registration Accept -> S1AP InitialContextSetupRequest (MME-UE=%ld, ENB-UE=%ld, NAS=%zu bytes)\n",
               mme_ue_id, enb_ue_id, downlink_nas_len);
        fflush(stdout);
        return 0;
    }

send_downlink_nas_transport:

    // Trace Downlink NAS before wrapping into S1AP
    if (downlink_nas && downlink_nas_len > 0) {
        size_t dump = 0;
        printf("[TRACE] [DLNAS] NAS-PDU head: ");
        for (; dump < 24 && dump < downlink_nas_len; ++dump) printf("%02X ", downlink_nas[dump]);
        if (downlink_nas_len > dump) printf("...");
        printf("\n");
        uint32_t crc = s1n2_crc32(downlink_nas, downlink_nas_len);
        size_t inner_off = 0;
        // If integrity-protected, inner plain starts at 6
        if (downlink_nas_len >= 6 && (downlink_nas[0] & 0xF0) == 0x10) inner_off = 6;
        uint32_t crc_inner = (downlink_nas_len > inner_off) ? s1n2_crc32(downlink_nas + inner_off, downlink_nas_len - inner_off) : 0;
        printf("[TRACE] [DLNAS] CRC32 full=0x%08X, inner@%zu=0x%08X (len=%zu)\n",
               crc, inner_off, crc_inner, downlink_nas_len - inner_off);
        if (downlink_nas_len > inner_off + 4) {
            const uint8_t *p = downlink_nas + inner_off;
            printf("[TRACE] [DLNAS] inner-AA octets: %02X %02X %02X %02X %02X\n", p[0], p[1], p[2], p[3], p[4]);
            if (p[0]==0x07 && p[1]==0x42 && p[3]==0x5A) {
                uint8_t v = p[4];
                uint8_t unit = (uint8_t)((v & 0xE0) >> 5);
                uint8_t val = (uint8_t)(v & 0x1F);
                int approx_min = -1;
                if (unit==1) approx_min = val;
                else if (unit==2) approx_min = val*6;
                else if (unit==0) {
                    printf("[TRACE] [DLNAS] inner T3412: unit=2sec, value=%u (~%u sec)\n", val, (unsigned)(val*2));
                }
                if (approx_min >= 0) {
                    printf("[TRACE] [DLNAS] inner T3412: IEI=0x5A, value=0x%02X (unit=%u, ~%d min)\n", v, unit, approx_min);
                } else if (unit!=0) {
                    printf("[TRACE] [DLNAS] inner T3412: IEI=0x5A, value=0x%02X (unit=%u)\n", v, unit);
                }
            }
        }
    }

    size_t out_len = *s1ap_len;
    int rc = build_s1ap_downlink_nas(s1ap_data, &out_len, mme_ue_id, enb_ue_id,
                                     downlink_nas, downlink_nas_len);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);

    if (rc != 0) {
        printf("[ERROR] Failed to build S1AP DownlinkNASTransport\n");
        fflush(stdout);
        return -1;
    }

    *s1ap_len = out_len;
    printf("[INFO] Converted NGAP DownlinkNASTransport to S1AP (MME-UE=%ld, ENB-UE=%ld, NAS=%zu bytes)\n",
           mme_ue_id, enb_ue_id, downlink_nas_len);
    fflush(stdout);
    return 0;
}
