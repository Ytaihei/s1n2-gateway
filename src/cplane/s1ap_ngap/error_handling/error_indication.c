/**
 * @file error_indication.c
 * @brief NGAP ErrorIndication builder + S1AP handler
 *
 * Builder:  build_ngap_error_indication()
 *   – extracted from protocol_builders.c
 * Handler:  s1n2_handle_s1ap_error_indication()
 *   – extracted from s1ap_dispatcher.c
 */
#include "internal/s1n2_converter_internal.h"
#include "error_handling.h"

/* NGAP ASN.1 types */
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_Criticality.h"
#include "NGAP_ErrorIndication.h"
#include "NGAP_Cause.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_ProcedureCode.h"

/* S1AP ASN.1 types (for handler IE extraction) */
#include "S1AP_ErrorIndication.h"
#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_ProtocolIE-ID.h"
#include "S1AP_Cause.h"

/* ================================================================== */
/* build_ngap_error_indication                                        */
/* ================================================================== */
int build_ngap_error_indication(uint8_t *buffer, size_t *buffer_len,
                                long amf_ue_ngap_id, long ran_ue_ngap_id,
                                const NGAP_Cause_t *cause) {
    if (!buffer || !buffer_len || !cause) return -1;

    NGAP_NGAP_PDU_t *pdu = calloc(1, sizeof(NGAP_NGAP_PDU_t));
    if (!pdu) return -1;

    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage) goto fail;

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = NGAP_ProcedureCode_id_ErrorIndication;
    init->criticality = NGAP_Criticality_ignore;
    init->value.present = NGAP_InitiatingMessage__value_PR_ErrorIndication;

    NGAP_ErrorIndication_t *msg = &init->value.choice.ErrorIndication;

    if (amf_ue_ngap_id > 0) {
        NGAP_ErrorIndicationIEs_t *ie = calloc(1, sizeof(*ie));
        if (!ie) goto fail;
        ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
        ie->criticality = NGAP_Criticality_ignore;
        ie->value.present = NGAP_ErrorIndicationIEs__value_PR_AMF_UE_NGAP_ID;
        if (asn_long2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_ue_ngap_id) != 0) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_ErrorIndicationIEs, ie);
            free(ie);
            goto fail;
        }
        ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);
    }

    if (ran_ue_ngap_id > 0) {
        NGAP_ErrorIndicationIEs_t *ie = calloc(1, sizeof(*ie));
        if (!ie) goto fail;
        ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
        ie->criticality = NGAP_Criticality_ignore;
        ie->value.present = NGAP_ErrorIndicationIEs__value_PR_RAN_UE_NGAP_ID;
        ie->value.choice.RAN_UE_NGAP_ID = ran_ue_ngap_id;
        ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);
    }

    NGAP_ErrorIndicationIEs_t *cause_ie = calloc(1, sizeof(*cause_ie));
    if (!cause_ie) goto fail;
    cause_ie->id = NGAP_ProtocolIE_ID_id_Cause;
    cause_ie->criticality = NGAP_Criticality_ignore;
    cause_ie->value.present = NGAP_ErrorIndicationIEs__value_PR_Cause;
    memcpy(&cause_ie->value.choice.Cause, cause, sizeof(NGAP_Cause_t));
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, cause_ie);

    if (asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, pdu, NULL, NULL) != 0) goto fail;

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, pdu, buffer, *buffer_len);
    if (er.encoded == -1) goto fail;

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *buffer_len) goto fail;
    *buffer_len = bytes;

    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return 0;

fail:
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return -1;
}

/* ================================================================== */
/* s1n2_handle_s1ap_error_indication                                  */
/* ================================================================== */
int s1n2_handle_s1ap_error_indication(s1n2_context_t *ctx, void *raw_msg) {
    S1AP_ErrorIndication_t *msg = (S1AP_ErrorIndication_t *)raw_msg;
    if (!msg) return -1;

    long enb_id = -1;
    long mme_id = -1;
    S1AP_Cause_t *s1ap_cause = NULL;
    bool has_diag = false;

    for (int i = 0; i < msg->protocolIEs.list.count; ++i) {
        S1AP_ErrorIndicationIEs_t *ie = msg->protocolIEs.list.array[i];
        if (!ie) continue;
        switch (ie->id) {
            case S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID:
                if (ie->value.present == S1AP_ErrorIndicationIEs__value_PR_ENB_UE_S1AP_ID)
                    enb_id = ie->value.choice.ENB_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID:
                if (ie->value.present == S1AP_ErrorIndicationIEs__value_PR_MME_UE_S1AP_ID)
                    mme_id = ie->value.choice.MME_UE_S1AP_ID;
                break;
            case S1AP_ProtocolIE_ID_id_Cause:
                if (ie->value.present == S1AP_ErrorIndicationIEs__value_PR_Cause)
                    s1ap_cause = &ie->value.choice.Cause;
                break;
            case S1AP_ProtocolIE_ID_id_CriticalityDiagnostics:
                has_diag = true;
                break;
            default:
                break;
        }
    }

    ue_id_mapping_t *map = NULL;
    if (ctx) {
        if (enb_id >= 0)
            map = s1n2_context_find_mapping_by_enb(ctx, enb_id);
        if (!map && mme_id >= 0)
            map = s1n2_context_find_mapping_by_amf(ctx, mme_id);
    }

    long ran_ue_ngap_id = map ? map->ran_ue_ngap_id : -1;
    long amf_ue_ngap_id = map ? map->amf_ue_ngap_id : -1;

    NGAP_Cause_t ngap_cause;
    s1n2_copy_s1ap_cause_to_ngap(s1ap_cause, &ngap_cause);
    long s1ap_cause_value = s1n2_get_s1ap_cause_value(s1ap_cause);

    printf("[WARN] Detected S1AP ErrorIndication (ENB=%ld, MME=%ld, diag=%d)\n",
           enb_id, mme_id, has_diag);
    printf("[WARN] [BRIDGE] Mapping -> RAN=%ld, AMF=%ld (map=%s)\n",
           ran_ue_ngap_id, amf_ue_ngap_id, map ? "hit" : "miss");
    printf("[WARN] [BRIDGE] Cause present=%d value=%ld\n",
           s1ap_cause ? s1ap_cause->present : -1, s1ap_cause_value);

    uint8_t ngap_buf[512];
    size_t ngap_len = sizeof(ngap_buf);
    int build_rc = build_ngap_error_indication(ngap_buf, &ngap_len,
                                               amf_ue_ngap_id, ran_ue_ngap_id,
                                               &ngap_cause);
    if (build_rc == 0) {
        if (ctx && ctx->n2_fd > 0) {
            ssize_t sent = sctp_sendmsg(ctx->n2_fd, ngap_buf, ngap_len,
                                        NULL, 0, htonl(60), 0, 0, 0, 0);
            if (sent == (ssize_t)ngap_len) {
                printf("[WARN] [BRIDGE] ErrorIndication forwarded to NGAP (%zd bytes, PPID=60)\n", sent);
            } else {
                printf("[ERROR] Failed to forward ErrorIndication to NGAP (ret=%zd, errno=%d)\n",
                       sent, errno);
            }
        } else {
            printf("[WARN] Cannot forward ErrorIndication: N2 socket unavailable\n");
        }
    } else {
        printf("[ERROR] Failed to build NGAP ErrorIndication\n");
    }

    fflush(stdout);
    return 0;
}
