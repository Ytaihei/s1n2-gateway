#include "s1n2_log.h"
/**
 * @file s1_setup_request.c
 * @brief S1AP S1SetupRequest to NGAP NGSetupRequest conversion
 *
 * Handles the S1 setup procedure: decodes S1SetupRequest from eNB,
 * converts to NGAP NGSetupRequest, and sends to AMF.
 */
#include "internal/s1n2_converter_internal.h"

int s1n2_convert_s1setup_to_ngsetup(uint8_t *s1ap_data, size_t s1ap_len,
                                    uint8_t *ngap_data, size_t *ngap_len) {
    if (!ngap_data || !ngap_len || *ngap_len < 1024) {
        return -1;
    }

    char mcc_buf[4] = {0};
    char mnc_buf[4] = {0};
    long tac_val = -1;
    uint32_t gnb_id = 1;
    char ran_name_buf[64] = {0};

    S1AP_S1AP_PDU_t *pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_S1AP_S1AP_PDU,
                                             (void **)&pdu, s1ap_data, s1ap_len);
    if (dr.code == RC_OK && pdu && pdu->present == S1AP_S1AP_PDU_PR_initiatingMessage) {
        S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
        if (init && init->value.present == S1AP_InitiatingMessage__value_PR_S1SetupRequest) {
            S1AP_S1SetupRequest_t *req = &init->value.choice.S1SetupRequest;
            for (int i = 0; i < req->protocolIEs.list.count; ++i) {
                S1AP_S1SetupRequestIEs_t *ie = req->protocolIEs.list.array[i];
                if (!ie) {
                    continue;
                }

                switch (ie->id) {
                    case S1AP_ProtocolIE_ID_id_Global_ENB_ID: {
                        if (ie->value.present == S1AP_S1SetupRequestIEs__value_PR_Global_ENB_ID) {
                            S1AP_Global_ENB_ID_t *g = &ie->value.choice.Global_ENB_ID;
                            if (g->pLMNidentity.size >= 3) {
                                const uint8_t *b = g->pLMNidentity.buf;
                                int mcc1 = b[0] & 0x0F;
                                int mcc2 = (b[0] >> 4) & 0x0F;
                                int mcc3 = b[1] & 0x0F;
                                int mnc3 = (b[1] >> 4) & 0x0F;
                                int mnc1 = b[2] & 0x0F;
                                int mnc2 = (b[2] >> 4) & 0x0F;
                                mcc_buf[0] = '0' + mcc1;
                                mcc_buf[1] = '0' + mcc2;
                                mcc_buf[2] = '0' + mcc3;
                                mcc_buf[3] = '\0';
                                if (mnc3 == 0xF) {
                                    mnc_buf[0] = '0' + mnc1;
                                    mnc_buf[1] = '0' + mnc2;
                                    mnc_buf[2] = '\0';
                                } else {
                                    mnc_buf[0] = '0' + mnc1;
                                    mnc_buf[1] = '0' + mnc2;
                                    mnc_buf[2] = '0' + mnc3;
                                    mnc_buf[3] = '\0';
                                }
                            }
                        }
                        break;
                    }
                    case S1AP_ProtocolIE_ID_id_eNBname: {
                        if (ie->value.present == S1AP_S1SetupRequestIEs__value_PR_ENBname) {
                            int copy = ie->value.choice.ENBname.size < (int)sizeof(ran_name_buf) - 1
                                         ? ie->value.choice.ENBname.size
                                         : (int)sizeof(ran_name_buf) - 1;
                            memcpy(ran_name_buf, ie->value.choice.ENBname.buf, copy);
                            ran_name_buf[copy] = '\0';
                        }
                        break;
                    }
                    case S1AP_ProtocolIE_ID_id_SupportedTAs: {
                        if (ie->value.present == S1AP_S1SetupRequestIEs__value_PR_SupportedTAs) {
                            S1AP_SupportedTAs_t *tas = &ie->value.choice.SupportedTAs;
                            if (tas->list.count > 0 && tas->list.array[0]->tAC.size >= 3) {
                                const uint8_t *t = tas->list.array[0]->tAC.buf;
                                tac_val = ((long)t[0] << 16) | ((long)t[1] << 8) | (long)t[2];
                            }
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
        }
    } else {
        LOG_WARN("S1AP decode failed or not S1SetupRequest (code=%d)\n", dr.code);

    }

    if (pdu) {
        ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
    }

    const char *env_mcc = (mcc_buf[0] ? mcc_buf : NULL);
    if (!env_mcc) env_mcc = getenv("S1N2_MCC");
    if (!env_mcc || !*env_mcc) env_mcc = getenv("MCC");
    if (!env_mcc || !*env_mcc) env_mcc = "001";

    const char *env_mnc = (mnc_buf[0] ? mnc_buf : NULL);
    if (!env_mnc) env_mnc = getenv("S1N2_MNC");
    if (!env_mnc || !*env_mnc) env_mnc = getenv("MNC");
    if (!env_mnc || !*env_mnc) env_mnc = "01";

    if (tac_val < 0) {
        const char *et = getenv("S1N2_TAC");
        if (!et || !*et) et = getenv("TAC");
        if (!et || !*et) et = "1";
        tac_val = strtol(et, NULL, 10);
    }

    const char *env_name = (ran_name_buf[0] ? ran_name_buf : NULL);
    if (!env_name) {
        env_name = getenv("S1N2_RAN_NAME");
        if (!env_name || !*env_name) env_name = "s1n2-gNB";
    }

    size_t dyn_len = *ngap_len;
    int enc = build_ngsetup_request_args(ngap_data, &dyn_len,
                                         env_mcc, env_mnc, tac_val, gnb_id, env_name);
    if (enc > 0) {
        *ngap_len = dyn_len;
        LOG_INFO("Dynamic NGSetupRequest encoded (%zu bytes)\n", dyn_len);

        return 0;
    }

    LOG_ERROR("build_ngsetup_request_args failed\n");

    return -1;
}
