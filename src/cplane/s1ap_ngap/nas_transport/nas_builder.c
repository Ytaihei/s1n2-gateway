/**
 * @file nas_builder.c
 * @brief NAS Transport PDU builder functions
 *
 * Extracted from protocol_builders.c — builds S1AP/NGAP
 * DownlinkNASTransport and UplinkNASTransport PDUs.
 *
 * These are low-level ASN.1 message encoders with no dependency
 * on converter state (s1n2_context_t).
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "s1n2_utils.h"
#include "internal/protocol_builders.h"

/* ASN.1 runtime */
#include <asn_application.h>
#include <aper_decoder.h>

/* S1AP headers */
#include "S1AP_S1AP-PDU.h"
#include "S1AP_InitiatingMessage.h"
#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_ProtocolIE-ID.h"
#include "S1AP_NAS-PDU.h"
#include "S1AP_DownlinkNASTransport.h"
#include "S1AP_ProcedureCode.h"

/* NGAP headers */
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_DownlinkNASTransport.h"
#include "NGAP_UplinkNASTransport.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_Criticality.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_UserLocationInformation.h"
#include "NGAP_UserLocationInformationNR.h"
#include "NGAP_NR-CGI.h"
#include "NGAP_TAI.h"
#include "NGAP_ProcedureCode.h"

/* ================================================================== */
/* build_s1ap_downlink_nas                                            */
/* ================================================================== */
int build_s1ap_downlink_nas(uint8_t *buffer, size_t *buffer_len,
                            long mme_ue_s1ap_id, long enb_ue_s1ap_id,
                            const uint8_t *nas_pdu, size_t nas_pdu_len) {
    if (!buffer || !buffer_len || !nas_pdu || nas_pdu_len == 0)
        return -1;

    S1AP_S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_S1AP_PDU_t));
    if (!pdu)
        return -1;

    pdu->present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(S1AP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage)
        goto fail;

    S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = S1AP_ProcedureCode_id_downlinkNASTransport;
    init->criticality = S1AP_Criticality_ignore;
    init->value.present = S1AP_InitiatingMessage__value_PR_DownlinkNASTransport;

    S1AP_DownlinkNASTransport_t *msg = &init->value.choice.DownlinkNASTransport;

    S1AP_DownlinkNASTransport_IEs_t *ie = calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.MME_UE_S1AP_ID = (unsigned long)mme_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = (long)enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(S1AP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_DownlinkNASTransport_IEs__value_PR_NAS_PDU;
    if (OCTET_STRING_fromBuf(&ie->value.choice.NAS_PDU, (const char *)nas_pdu, nas_pdu_len) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_DownlinkNASTransport_IEs, ie);
        free(ie);
        goto fail;
    }
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    if (asn_check_constraints(&asn_DEF_S1AP_S1AP_PDU, pdu, NULL, NULL) != 0)
        goto fail;

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_S1AP_S1AP_PDU, NULL, pdu, buffer, *buffer_len);
    if (er.encoded == -1)
        goto fail;

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *buffer_len)
        goto fail;
    *buffer_len = bytes;

    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
    return 0;

fail:
    ASN_STRUCT_FREE(asn_DEF_S1AP_S1AP_PDU, pdu);
    return -1;
}

/* ================================================================== */
/* build_ngap_downlink_nas                                            */
/* ================================================================== */
int build_ngap_downlink_nas(uint8_t *buffer, size_t *buffer_len,
                            long amf_ue_ngap_id, long ran_ue_ngap_id,
                            const uint8_t *nas_pdu, size_t nas_pdu_len) {
    if (!buffer || !buffer_len || !nas_pdu || nas_pdu_len == 0)
        return -1;

    NGAP_NGAP_PDU_t *pdu = calloc(1, sizeof(NGAP_NGAP_PDU_t));
    if (!pdu)
        return -1;

    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage)
        goto fail;

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = NGAP_ProcedureCode_id_DownlinkNASTransport;
    init->criticality = NGAP_Criticality_ignore;
    init->value.present = NGAP_InitiatingMessage__value_PR_DownlinkNASTransport;

    NGAP_DownlinkNASTransport_t *msg = &init->value.choice.DownlinkNASTransport;

    NGAP_DownlinkNASTransport_IEs_t *ie = calloc(1, sizeof(NGAP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_DownlinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
    if (asn_long2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_ue_ngap_id) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_DownlinkNASTransport_IEs, ie);
        free(ie);
        goto fail;
    }
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(NGAP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_DownlinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;
    ie->value.choice.RAN_UE_NGAP_ID = ran_ue_ngap_id;
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(NGAP_DownlinkNASTransport_IEs_t));
    if (!ie)
        goto fail;
    ie->id = NGAP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_DownlinkNASTransport_IEs__value_PR_NAS_PDU;
    ie->value.choice.NAS_PDU.size = nas_pdu_len;
    ie->value.choice.NAS_PDU.buf = calloc(nas_pdu_len, sizeof(uint8_t));
    if (!ie->value.choice.NAS_PDU.buf) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_DownlinkNASTransport_IEs, ie);
        free(ie);
        goto fail;
    }
    memcpy(ie->value.choice.NAS_PDU.buf, nas_pdu, nas_pdu_len);
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    if (asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, pdu, NULL, NULL) != 0)
        goto fail;

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, pdu, buffer, *buffer_len);
    if (er.encoded == -1)
        goto fail;

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *buffer_len)
        goto fail;
    *buffer_len = bytes;

    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return 0;

fail:
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return -1;
}

/* ================================================================== */
/* build_ngap_uplink_nas                                              */
/* ================================================================== */
int build_ngap_uplink_nas(uint8_t *buffer, size_t *buffer_len,
                          long amf_ue_ngap_id, long ran_ue_ngap_id,
                          const uint8_t *nas_pdu, size_t nas_pdu_len,
                          const uint8_t *plmn_id, size_t plmn_id_len,
                          uint32_t cell_id, uint16_t tac) {
    const char *fail_stage = "arg-check";
    if (!buffer || !buffer_len || !nas_pdu || nas_pdu_len == 0) {
        printf("[ERROR] build_ngap_uplink_nas invalid args (nas_len=%zu)\n", nas_pdu_len);
        fflush(stdout);
        return -1;
    }

    fail_stage = "alloc-ngap-pdu";
    NGAP_NGAP_PDU_t *pdu = calloc(1, sizeof(NGAP_NGAP_PDU_t));
    if (!pdu) {
        printf("[ERROR] build_ngap_uplink_nas failed to allocate NGAP_PDU\n");
        fflush(stdout);
        return -1;
    }

    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    fail_stage = "alloc-initiating";
    pdu->choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage)
        goto fail;

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = NGAP_ProcedureCode_id_UplinkNASTransport;
    init->criticality = NGAP_Criticality_ignore;
    init->value.present = NGAP_InitiatingMessage__value_PR_UplinkNASTransport;

    NGAP_UplinkNASTransport_t *msg = &init->value.choice.UplinkNASTransport;

    NGAP_UplinkNASTransport_IEs_t *ie = calloc(1, sizeof(NGAP_UplinkNASTransport_IEs_t));
    if (!ie) { fail_stage = "alloc-ran-ue"; goto fail; }
    ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_UplinkNASTransport_IEs__value_PR_RAN_UE_NGAP_ID;
    ie->value.choice.RAN_UE_NGAP_ID = ran_ue_ngap_id;
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(NGAP_UplinkNASTransport_IEs_t));
    if (!ie) { fail_stage = "alloc-amf-ue"; goto fail; }
    ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_UplinkNASTransport_IEs__value_PR_AMF_UE_NGAP_ID;
    if (asn_long2INTEGER(&ie->value.choice.AMF_UE_NGAP_ID, amf_ue_ngap_id) != 0) {
        fail_stage = "assign-amf-ue";
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
        free(ie);
        goto fail;
    }
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    ie = calloc(1, sizeof(NGAP_UplinkNASTransport_IEs_t));
    if (!ie) { fail_stage = "alloc-nas"; goto fail; }
    ie->id = NGAP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_UplinkNASTransport_IEs__value_PR_NAS_PDU;
    ie->value.choice.NAS_PDU.size = nas_pdu_len;
    ie->value.choice.NAS_PDU.buf = calloc(nas_pdu_len, sizeof(uint8_t));
    if (!ie->value.choice.NAS_PDU.buf) {
        fail_stage = "alloc-nas-buf";
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
        free(ie);
        goto fail;
    }
    memcpy(ie->value.choice.NAS_PDU.buf, nas_pdu, nas_pdu_len);
    ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

    /* UserLocationInformation IE (mandatory) */
    if (plmn_id && plmn_id_len > 0) {
        ie = calloc(1, sizeof(NGAP_UplinkNASTransport_IEs_t));
        if (!ie) { fail_stage = "alloc-userloc-ie"; goto fail; }
        ie->id = NGAP_ProtocolIE_ID_id_UserLocationInformation;
        ie->criticality = NGAP_Criticality_reject;
        ie->value.present = NGAP_UplinkNASTransport_IEs__value_PR_UserLocationInformation;

        NGAP_UserLocationInformation_t *loc = &ie->value.choice.UserLocationInformation;
        loc->present = NGAP_UserLocationInformation_PR_userLocationInformationNR;

        NGAP_UserLocationInformationNR_t *nr_loc = calloc(1, sizeof(NGAP_UserLocationInformationNR_t));
        if (!nr_loc) {
            fail_stage = "alloc-userloc-nr";
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
            free(ie);
            goto fail;
        }
        loc->choice.userLocationInformationNR = nr_loc;

        nr_loc->nR_CGI.pLMNIdentity.size = plmn_id_len;
        nr_loc->nR_CGI.pLMNIdentity.buf = calloc(plmn_id_len, sizeof(uint8_t));
        if (!nr_loc->nR_CGI.pLMNIdentity.buf) {
            fail_stage = "alloc-plmn";
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
            free(ie);
            goto fail;
        }
        memcpy(nr_loc->nR_CGI.pLMNIdentity.buf, plmn_id, plmn_id_len);

        nr_loc->nR_CGI.nRCellIdentity.size = 5;
        nr_loc->nR_CGI.nRCellIdentity.bits_unused = 4;
        nr_loc->nR_CGI.nRCellIdentity.buf = calloc(5, sizeof(uint8_t));
        if (!nr_loc->nR_CGI.nRCellIdentity.buf) {
            fail_stage = "alloc-nrcgi";
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
            free(ie);
            goto fail;
        }
        nr_loc->nR_CGI.nRCellIdentity.buf[0] = (cell_id >> 28) & 0xFF;
        nr_loc->nR_CGI.nRCellIdentity.buf[1] = (cell_id >> 20) & 0xFF;
        nr_loc->nR_CGI.nRCellIdentity.buf[2] = (cell_id >> 12) & 0xFF;
        nr_loc->nR_CGI.nRCellIdentity.buf[3] = (cell_id >> 4) & 0xFF;
        nr_loc->nR_CGI.nRCellIdentity.buf[4] = (cell_id << 4) & 0xF0;

        nr_loc->tAI.pLMNIdentity.size = plmn_id_len;
        nr_loc->tAI.pLMNIdentity.buf = calloc(plmn_id_len, sizeof(uint8_t));
        if (!nr_loc->tAI.pLMNIdentity.buf) {
            fail_stage = "alloc-tai-plmn";
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
            free(ie);
            goto fail;
        }
        memcpy(nr_loc->tAI.pLMNIdentity.buf, plmn_id, plmn_id_len);

        nr_loc->tAI.tAC.size = 3;
        nr_loc->tAI.tAC.buf = calloc(3, sizeof(uint8_t));
        if (!nr_loc->tAI.tAC.buf) {
            fail_stage = "alloc-tac";
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_UplinkNASTransport_IEs, ie);
            free(ie);
            goto fail;
        }
        nr_loc->tAI.tAC.buf[0] = (tac >> 16) & 0xFF;
        nr_loc->tAI.tAC.buf[1] = (tac >> 8) & 0xFF;
        nr_loc->tAI.tAC.buf[2] = tac & 0xFF;

        ASN_SEQUENCE_ADD(&msg->protocolIEs.list, ie);

        printf("[DEBUG] Added UserLocationInformation to UplinkNASTransport (PLMN len=%zu, Cell ID=0x%X, TAC=%u)\n",
               plmn_id_len, cell_id, tac);
        fflush(stdout);
    }

    if (asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, pdu, NULL, NULL) != 0) {
        fail_stage = "constraints";
        goto fail;
    }

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, pdu, buffer, *buffer_len);
    if (er.encoded == -1) { fail_stage = "aper-encode"; goto fail; }

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *buffer_len) { fail_stage = "buffer-too-small"; goto fail; }
    *buffer_len = bytes;

    uint32_t encoded_crc = s1n2_crc32(buffer, *buffer_len);
    printf("[TRACE] build_ngap_uplink_nas success (bytes=%zu CRC=0x%08X AMF=%ld RAN=%ld)\n",
           *buffer_len, encoded_crc, amf_ue_ngap_id, ran_ue_ngap_id);
    fflush(stdout);

    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return 0;

fail:
    printf("[ERROR] build_ngap_uplink_nas failed at stage=%s (AMF=%ld RAN=%ld NAS=%zu PLMN_len=%zu)\n",
           fail_stage, amf_ue_ngap_id, ran_ue_ngap_id, nas_pdu_len, plmn_id_len);
    fflush(stdout);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return -1;
}
