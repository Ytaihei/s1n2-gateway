#include "registration/registration_bridge.h"
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

int s1n2_convert_ngap_downlink_nas_transport(s1n2_context_t *ctx,
                                             uint8_t *ngap_data, size_t ngap_len,
                                             uint8_t *s1ap_data, size_t *s1ap_len) {
    if (!ngap_data || !s1ap_data || !s1ap_len || *s1ap_len == 0)
        return -1;

    NGAP_NGAP_PDU_t *pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_NGAP_NGAP_PDU, (void**)&pdu, ngap_data, ngap_len);
    if (dr.code != RC_OK || !pdu || pdu->present != NGAP_NGAP_PDU_PR_initiatingMessage) {
        LOG_ERROR("Failed to decode NGAP DownlinkNASTransport (code=%d)\n", dr.code);

        if (pdu) ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        return -1;
    }

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    if (!init || init->procedureCode != NGAP_ProcedureCode_id_DownlinkNASTransport ||
        init->value.present != NGAP_InitiatingMessage__value_PR_DownlinkNASTransport) {
        LOG_ERROR("NGAP message is not DownlinkNASTransport (proc=%ld)\n",
               init ? (long)init->procedureCode : -1);

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
                        LOG_WARN("Failed to decode AMF-UE NGAP ID\n");
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
        LOG_ERROR("NGAP DownlinkNASTransport missing NAS-PDU\n");

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
            LOG_DEBUG("UE mapping applied for DownlinkNASTransport (RAN=%ld -> ENB=%ld, MME=%ld)\n",
                   ran_ue_id, enb_ue_id, mme_ue_id);

        } else {
            LOG_WARN("UE mapping not found for DownlinkNASTransport (RAN=%ld, AMF=%ld)\n",
                   ran_ue_id, amf_ue_id);

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
                LOG_INFO("Created new UE mapping for Authentication Request (RAN=%ld, AMF=%ld)\n",
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
                LOG_INFO("[SQN-FIX] Extracted and cached SQN^AK from 5G Auth Request\n");

                LOG_INFO("Cached RAND/AUTN/ABBA for UE (RAN-UE-ID=%ld, AMF-UE-ID=%ld)\n",
                       ran_ue_id, amf_ue_id);

                if (!cache_map->has_nas_keys && cache_map->imsi[0] != '\0') {
                    if (s1n2_try_derive_4g_nas_keys(ctx, cache_map) == 0) {
                        LOG_INFO("[NAS-KEY] Derived NAS keys immediately after Auth Request\n");

                    }
                }
                ue_map = cache_map;
            } else {
                LOG_WARN("Could not find or create UE mapping to cache RAND\n");
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
        LOG_WARN("NAS-PDU length %zu exceeds 4G buffer size, forwarding original 5G NAS\n", nas_len);
    } else {
    int conversion_rc = convert_5g_nas_to_4g(nas_buf, nas_len, nas_4g_buf, &nas_4g_len, &sm_info, ue_map);
    if (conversion_rc == 1) {
        int rc = s1n2_start_registration_session(ctx, ue_map);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        *s1ap_len = 0;
        return rc;
    }
    if (conversion_rc == 0) {
            downlink_nas = nas_4g_buf;
            downlink_nas_len = nas_4g_len;
            nas_converted = true;
            LOG_INFO("DownlinkNASTransport: 5G NAS converted to 4G NAS (5G len=%zu, 4G len=%zu)\n",
                   nas_len, nas_4g_len);
        } else {
            LOG_WARN("DownlinkNASTransport: NAS conversion failed; dropping\n");
            ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
            return -1;
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
         LOG_DEBUG("[COUNT-RESET] Before reset: nas_ul_count_5g=0x%08X (RAN=%ld, AMF=%ld)\n",
             security_map->nas_ul_count_5g, ran_ue_id, amf_ue_id);
         security_map->nas_ul_count_5g = 0;
         security_map->nas_dl_count_5g = 0;
         security_map->has_nas_dl_count_5g = false;
         LOG_INFO("[COUNT-RESET] Reset NAS UL COUNT to 0 for new security context (RAN=%ld, AMF=%ld)\n",
             ran_ue_id, amf_ue_id);

         LOG_INFO("Cached Security Mode info for UE (RAN=%ld, AMF=%ld) - alg=0x%02X, ngKSI=0x%02X\n",
             ran_ue_id, amf_ue_id, sm_info.selected_alg_4g, sm_info.ngksi);
        } else {
            LOG_WARN("Failed to cache security mode info (no UE mapping)\n");
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
            LOG_DEBUG("[ICS-TRIGGER] Detected plain Attach Accept (0x07 0x42)\n");
        }
        // Case 2: integrity-only protected EPS NAS (0x17).
        // Format: [SecHdr(1)] [MAC(4)] [SEQ(1)] [Plain EPS NAS starting at 0x07 0x42 ...]
        else if (downlink_nas_len >= 8 && downlink_nas[0] == 0x17) {
            if (downlink_nas[6] == 0x07 && downlink_nas[7] == 0x42) {
                is_attach_accept = true;
                attach_plain_off = 6; // skip MAC(4) + SEQ(1) plus 1-byte sec hdr
                LOG_DEBUG("[ICS-TRIGGER] Detected integrity-protected Attach Accept (0x17, plain at offset 6)\n");
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
                LOG_INFO("[ICS] Already sent InitialContextSetup for UE (ENB=%ld) %.1f seconds ago, skipping duplicate\n",
                       enb_ue_id, elapsed);
                LOG_INFO("Sending DownlinkNASTransport instead\n");
                // Fall through to send DownlinkNASTransport instead
                goto send_downlink_nas_transport;
            } else {
                // More than 10 seconds elapsed, allow retry (UE may have detached and re-attached)
                LOG_WARN("[ICS] Allowing ICS retry after %.1f seconds (ENB=%ld)\n", elapsed, enb_ue_id);
            }
        } else if (ue_map && ue_map->ics_completed) {
            // ICS already completed, don't re-send; forward as DownlinkNAS
            LOG_INFO("[ICS] Already completed for UE (ENB=%ld), forwarding as DownlinkNAS\n", enb_ue_id);
            goto send_downlink_nas_transport;
        } else if (ue_map && ue_map->ics_failed) {
            // Previous attempt failed; allow retry but consider tweaking EBI to avoid duplicate errors
            LOG_WARN("[ICS] Previous ICS failed for UE (ENB=%ld); will retry with adjusted parameters if needed\n", enb_ue_id);
        }

        uint32_t s1u_ip_be = 0;
        uint32_t s1u_teid_be = 0;
        uint8_t  e_rab_id = 5;
        s1n2_uplane_select_s1u_endpoint(ctx, ue_map, &s1u_ip_be, &s1u_teid_be, &e_rab_id);

        // If last attempt failed with duplicate E-RAB ID or we see quick retries, try alternate EBI (6..15)
        if (ue_map && ue_map->ics_failed) {
            uint8_t alt_ebi = (uint8_t)(5 + (ue_map->ics_attempts % 10));
            if (alt_ebi >= 6 && alt_ebi <= 15) {
                LOG_WARN("[ICS] Adjusting E-RAB ID from %u to %u to avoid duplicate instances\n", e_rab_id, alt_ebi);
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
            LOG_INFO("[ICS] Detected integrity-wrapped Attach Accept; embedding protected NAS as-is (len=%zu) into ICS\n",
                   ics_nas_len);
        } else {
            LOG_INFO("[ICS] Detected plain Attach Accept; embedding as-is (len=%zu) into ICS\n", ics_nas_len);
        }
        // NOTE: Do NOT send NGAP PDUSessionResourceSetupRequest to AMF here!
        // AMF does not have SMF context yet and will reject with "Cannot find PDU Session ID".
        // Proper 5G flow: AMF contacts SMF first, then AMF sends PDUSessionResourceSetupRequest to RAN.
        // For now, skip PDU Session setup entirely and let AMF/SMF handle it separately.

        int rc_ics = build_s1ap_initial_context_setup_request(s1ap_data, &ics_len,
                                                              mme_ue_id, enb_ue_id,
                                                              ics_nas_pdu, ics_nas_len,
                                                              e_rab_id, s1u_ip_be, s1u_teid_be,
                                                              (ue_map && ue_map->has_kenb) ? ue_map->kenb : NULL);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        if (rc_ics != 0) {
            LOG_ERROR("Failed to build S1AP InitialContextSetupRequest (from Attach Accept)\n");

            return -1;
        }
        *s1ap_len = ics_len;

        // Mark ICS as sent for this UE to prevent duplicates (in-flight)
        if (ue_map) {
            ue_map->ics_sent = true;
            ue_map->ics_sent_time = time(NULL);
            ue_map->ics_e_rab_id = e_rab_id;
            ue_map->ics_failed = false; // reset failure flag on new attempt
            LOG_INFO("[ICS] Marked ICS sent for UE (ENB=%ld, EBI=%u)\n", enb_ue_id, e_rab_id);

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

            LOG_INFO("[ICS] Stored E-RAB info for PDU Session: ID=%u, QCI=%u, QFI=%u, APN=%s\n",
                   ue_map->pdu_session_id, ue_map->qci, ue_map->qfi, ue_map->apn);
        }

        return 0;
    }

send_downlink_nas_transport:

    size_t out_len = *s1ap_len;
    int rc = build_s1ap_downlink_nas(s1ap_data, &out_len, mme_ue_id, enb_ue_id,
                                     downlink_nas, downlink_nas_len);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);

    if (rc != 0) {
        LOG_ERROR("Failed to build S1AP DownlinkNASTransport\n");

        return -1;
    }

    *s1ap_len = out_len;

    return 0;
}
