/**
 * @file initial_ue_builder.c
 * @brief NGAP InitialUEMessage builder using asn1c structures
 *
 * Builds NGAP InitialUEMessage from extracted S1AP parameters.
 * Extracted from ngap_builder.c during Phase 2 refactoring.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "s1n2_converter.h"

// asn1c generated headers
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProcedureCode.h"
#include "NGAP_Criticality.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_InitialUEMessage.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_NAS-PDU.h"
#include "NGAP_UserLocationInformation.h"
#include "NGAP_UserLocationInformationNR.h"
#include "NGAP_NGRAN-CGI.h"
#include "NGAP_TAI.h"
#include "NGAP_RRCEstablishmentCause.h"
#include "NGAP_UEContextRequest.h"
#include "NGAP_FiveG-S-TMSI.h"
#include <asn_application.h>
#include <asn_internal.h>
#include <aper_encoder.h>

static void hexdump(const char *tag, const uint8_t *buf, size_t len) {
    printf("[HEX] %s (%zu): ", tag, len);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if (i + 1 < len) putchar(' ');
    }
    putchar('\n');
}

// PLMN: MCC/MNC -> 3 octet BCD (TS 38.413 Annex) helper
static void encode_plmn(const char *mcc_in, const char *mnc_in, uint8_t out[3]) {
    char mcc[4] = {'0','0','0','\0'}; size_t lmcc = strlen(mcc_in);
    if (lmcc >= 3) { mcc[0]=mcc_in[lmcc-3]; mcc[1]=mcc_in[lmcc-2]; mcc[2]=mcc_in[lmcc-1]; }
    else if (lmcc == 2) { mcc[1]=mcc_in[0]; mcc[2]=mcc_in[1]; }
    else if (lmcc == 1) { mcc[2]=mcc_in[0]; }
    char mnc[4] = {'\0','\0','\0','\0'}; size_t lmnc = strlen(mnc_in);
    if (lmnc >= 3) { mnc[0]=mnc_in[lmnc-3]; mnc[1]=mnc_in[lmnc-2]; mnc[2]=mnc_in[lmnc-1]; }
    else if (lmnc == 2) { mnc[0]=mnc_in[0]; mnc[1]=mnc_in[1]; }
    else if (lmnc == 1) { mnc[0]=mnc_in[0]; mnc[1]='0'; }
    int mcc1=mcc[0]-'0', mcc2=mcc[1]-'0', mcc3=mcc[2]-'0';
    int mnc1=mnc[0]?mnc[0]-'0':0, mnc2=mnc[1]?mnc[1]-'0':0, mnc3=(lmnc>=3)?(mnc[2]-'0'):0xF;
    out[0] = (uint8_t)((mcc2<<4)|mcc1);
    out[1] = (uint8_t)((mnc3<<4)|mcc3);
    out[2] = (uint8_t)((mnc2<<4)|mnc1);
}

// Build NGAP InitialUEMessage dynamically
static int build_initial_ue_message_internal(uint8_t *buf, size_t *len,
    uint32_t ran_ue_ngap_id, const uint8_t *nas_pdu, size_t nas_pdu_len,
    const char *mcc, const char *mnc, long tac, uint32_t nr_cell_id,
    uint8_t rrc_cause, bool include_s_tmsi, uint32_t amf_set_id,
    uint8_t amf_pointer, uint32_t fiveg_tmsi, bool ue_context_requested) {

    // PDU and message allocation
    NGAP_NGAP_PDU_t pdu;
    NGAP_InitiatingMessage_t *initiatingMessage = NULL;
    NGAP_InitialUEMessage_t *InitialUEMessage = NULL;

    NGAP_InitialUEMessage_IEs_t *ie = NULL;
    NGAP_RAN_UE_NGAP_ID_t *RAN_UE_NGAP_ID = NULL;
    NGAP_NAS_PDU_t *NAS_PDU = NULL;
    NGAP_UserLocationInformation_t *UserLocationInformation = NULL;
    NGAP_UserLocationInformationNR_t *userLocationInformationNR = NULL;
    NGAP_NR_CGI_t *nR_CGI = NULL;
    NGAP_TAI_t *tAI = NULL;
    NGAP_RRCEstablishmentCause_t *RRCEstablishmentCause = NULL;
    NGAP_UEContextRequest_t *UEContextRequest = NULL;
    NGAP_FiveG_S_TMSI_t *FiveG_S_TMSI = NULL;

    memset(&pdu, 0, sizeof(NGAP_NGAP_PDU_t));
    pdu.present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));

    initiatingMessage = pdu.choice.initiatingMessage;
    initiatingMessage->procedureCode = NGAP_ProcedureCode_id_InitialUEMessage;
    initiatingMessage->criticality = NGAP_Criticality_ignore;
    initiatingMessage->value.present = NGAP_InitiatingMessage__value_PR_InitialUEMessage;

    InitialUEMessage = &initiatingMessage->value.choice.InitialUEMessage;

    // 1) RAN-UE-NGAP-ID
    ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
    ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_RAN_UE_NGAP_ID;
    RAN_UE_NGAP_ID = &ie->value.choice.RAN_UE_NGAP_ID;
    *RAN_UE_NGAP_ID = ran_ue_ngap_id;
    ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);

    // 2) NAS-PDU
    ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
    ie->id = NGAP_ProtocolIE_ID_id_NAS_PDU;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_NAS_PDU;
    NAS_PDU = &ie->value.choice.NAS_PDU;
    NAS_PDU->size = nas_pdu_len;
    NAS_PDU->buf = calloc(nas_pdu_len, sizeof(uint8_t));
    memcpy(NAS_PDU->buf, nas_pdu, nas_pdu_len);
    ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);

    // 3) UserLocationInformation
    ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
    ie->id = NGAP_ProtocolIE_ID_id_UserLocationInformation;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_UserLocationInformation;
    UserLocationInformation = &ie->value.choice.UserLocationInformation;

    userLocationInformationNR = calloc(1, sizeof(NGAP_UserLocationInformationNR_t));

    // NR-CGI
    nR_CGI = &userLocationInformationNR->nR_CGI;
    uint8_t plmn_enc[3];
    encode_plmn(mcc, mnc, plmn_enc);
    OCTET_STRING_fromBuf(&nR_CGI->pLMNIdentity, (char*)plmn_enc, 3);
    nR_CGI->nRCellIdentity.size = 5;
    nR_CGI->nRCellIdentity.buf = calloc(5, sizeof(uint8_t));
    nR_CGI->nRCellIdentity.buf[0] = (nr_cell_id >> 32) & 0xFF;
    nR_CGI->nRCellIdentity.buf[1] = (nr_cell_id >> 24) & 0xFF;
    nR_CGI->nRCellIdentity.buf[2] = (nr_cell_id >> 16) & 0xFF;
    nR_CGI->nRCellIdentity.buf[3] = (nr_cell_id >> 8) & 0xFF;
    nR_CGI->nRCellIdentity.buf[4] = nr_cell_id & 0xFF;
    nR_CGI->nRCellIdentity.bits_unused = 4;

    // TAI
    tAI = &userLocationInformationNR->tAI;
    OCTET_STRING_fromBuf(&tAI->pLMNIdentity, (char*)plmn_enc, 3);
    tAI->tAC.size = 3;
    tAI->tAC.buf = calloc(3, sizeof(uint8_t));
    uint32_t tac_val = tac & 0xFFFFFF;
    tAI->tAC.buf[0] = (tac_val >> 16) & 0xFF;
    tAI->tAC.buf[1] = (tac_val >> 8) & 0xFF;
    tAI->tAC.buf[2] = tac_val & 0xFF;

    UserLocationInformation->present = NGAP_UserLocationInformation_PR_userLocationInformationNR;
    UserLocationInformation->choice.userLocationInformationNR = userLocationInformationNR;
    ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);

    // 4) RRCEstablishmentCause
    ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
    ie->id = NGAP_ProtocolIE_ID_id_RRCEstablishmentCause;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_RRCEstablishmentCause;
    RRCEstablishmentCause = &ie->value.choice.RRCEstablishmentCause;
    *RRCEstablishmentCause = rrc_cause;
    ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);

    // 5) FiveG-S-TMSI (optional)
    if (include_s_tmsi) {
        ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
        ie->id = NGAP_ProtocolIE_ID_id_FiveG_S_TMSI;
        ie->criticality = NGAP_Criticality_reject;
        ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_FiveG_S_TMSI;
        FiveG_S_TMSI = &ie->value.choice.FiveG_S_TMSI;

        // AMFSetID
        FiveG_S_TMSI->aMFSetID.size = 2;
        FiveG_S_TMSI->aMFSetID.buf = calloc(2, sizeof(uint8_t));
        FiveG_S_TMSI->aMFSetID.buf[0] = (amf_set_id >> 8) & 0xFF;
        FiveG_S_TMSI->aMFSetID.buf[1] = amf_set_id & 0xFF;
        FiveG_S_TMSI->aMFSetID.bits_unused = 6;

        // AMFPointer
        FiveG_S_TMSI->aMFPointer.size = 1;
        FiveG_S_TMSI->aMFPointer.buf = calloc(1, sizeof(uint8_t));
        FiveG_S_TMSI->aMFPointer.buf[0] = amf_pointer & 0x3F;
        FiveG_S_TMSI->aMFPointer.bits_unused = 2;

        // FiveG-TMSI
        FiveG_S_TMSI->fiveG_TMSI.size = 4;
        FiveG_S_TMSI->fiveG_TMSI.buf = calloc(4, sizeof(uint8_t));
        FiveG_S_TMSI->fiveG_TMSI.buf[0] = (fiveg_tmsi >> 24) & 0xFF;
        FiveG_S_TMSI->fiveG_TMSI.buf[1] = (fiveg_tmsi >> 16) & 0xFF;
        FiveG_S_TMSI->fiveG_TMSI.buf[2] = (fiveg_tmsi >> 8) & 0xFF;
        FiveG_S_TMSI->fiveG_TMSI.buf[3] = fiveg_tmsi & 0xFF;

        ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);
    }

    // 6) UEContextRequest (optional)
    if (ue_context_requested) {
        ie = calloc(1, sizeof(NGAP_InitialUEMessage_IEs_t));
        ie->id = NGAP_ProtocolIE_ID_id_UEContextRequest;
        ie->criticality = NGAP_Criticality_ignore;
        ie->value.present = NGAP_InitialUEMessage_IEs__value_PR_UEContextRequest;
        UEContextRequest = &ie->value.choice.UEContextRequest;
        *UEContextRequest = NGAP_UEContextRequest_requested;
        ASN_SEQUENCE_ADD(&InitialUEMessage->protocolIEs, ie);
    }

    // Validate constraints for better diagnostics
    if (asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, &pdu, NULL, NULL) != 0) {
        printf("[ERROR] NGAP InitialUEMessage constraint check failed\n");
        fflush(stdout);
        return -1;
    }

    // Direct APER encoding
    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, &pdu, buf, *len);
    if (er.encoded == -1) {
        printf("[ERROR] aper_encode_to_buffer failed: %s\n", strerror(errno));
        fflush(stdout);
        return -1;
    }

    size_t out = er.encoded;
    if (out > *len) out = *len;
    *len = out;

    hexdump("InitialUEMessage(dynamic)", buf, out);
    return (int)out;
}

// Public interface for building InitialUEMessage
int build_initial_ue_message(uint8_t *buf, size_t *len,
    uint32_t ran_ue_ngap_id, const uint8_t *nas_pdu, size_t nas_pdu_len,
    const char *mcc, const char *mnc, long tac, uint32_t nr_cell_id,
    uint8_t rrc_cause, bool include_s_tmsi, uint32_t amf_set_id,
    uint8_t amf_pointer, uint32_t fiveg_tmsi, bool ue_context_requested) {

    return build_initial_ue_message_internal(buf, len, ran_ue_ngap_id, nas_pdu, nas_pdu_len,
        mcc, mnc, tac, nr_cell_id, rrc_cause, include_s_tmsi, amf_set_id,
        amf_pointer, fiveg_tmsi, ue_context_requested);
}
