/**
 * @file ngap_setup_request.c
 * @brief NGAP NGSetupRequest builder
 *
 * Builds NGAP NGSetupRequest message from parameters using asn1c structures.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "s1n2_converter.h"

// asn1c 生成ヘッダ（Open5GS asn1c ソースを明示インクルード）
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_NGSetupRequest.h"
#include "NGAP_ProcedureCode.h"
#include "NGAP_Criticality.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_GlobalRANNodeID.h"
#include "NGAP_GlobalGNB-ID.h"
#include "NGAP_SupportedTAList.h"
#include "NGAP_SupportedTAItem.h"
#include "NGAP_BroadcastPLMNItem.h"
#include "NGAP_PLMNIdentity.h"
#include "NGAP_TAC.h"
#include "NGAP_RANNodeName.h"
#include "NGAP_PagingDRX.h"
#include "NGAP_SliceSupportItem.h"
#include "NGAP_S-NSSAI.h"
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

// Build NGSetupRequest using asn1c structures; returns encoded size or -1
static int build_ngsetup_request_internal(uint8_t *buf, size_t *len,
    const char *mcc, const char *mnc, long tac, uint32_t gnb_id, const char *ran_name) {

    // PDU and message allocation
    NGAP_NGAP_PDU_t pdu;
    NGAP_InitiatingMessage_t *initiatingMessage = NULL;
    NGAP_NGSetupRequest_t *NGSetupRequest = NULL;

    NGAP_NGSetupRequestIEs_t *ie = NULL;
    NGAP_GlobalRANNodeID_t *GlobalRANNodeID = NULL;
    NGAP_RANNodeName_t *RANNodeName = NULL;
    NGAP_GlobalGNB_ID_t *globalGNB_ID = NULL;
    NGAP_SupportedTAList_t *SupportedTAList = NULL;
    NGAP_SupportedTAItem_t *SupportedTAItem = NULL;
    NGAP_BroadcastPLMNItem_t *BroadcastPLMNItem = NULL;
    NGAP_SliceSupportItem_t *SliceSupportItem = NULL;
    NGAP_PagingDRX_t *PagingDRX = NULL;

    memset(&pdu, 0, sizeof(NGAP_NGAP_PDU_t));
    pdu.present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
    if (!pdu.choice.initiatingMessage) return -1;

    initiatingMessage = pdu.choice.initiatingMessage;
    initiatingMessage->procedureCode = NGAP_ProcedureCode_id_NGSetup;
    initiatingMessage->criticality = NGAP_Criticality_reject;
    initiatingMessage->value.present = NGAP_InitiatingMessage__value_PR_NGSetupRequest;

    NGSetupRequest = &initiatingMessage->value.choice.NGSetupRequest;

    // Create globalGNB_ID first
    globalGNB_ID = calloc(1, sizeof(NGAP_GlobalGNB_ID_t));
    if (!globalGNB_ID) return -1;

    // Set PLMN Identity
    uint8_t plmn_enc[3];
    encode_plmn(mcc, mnc, plmn_enc);
    OCTET_STRING_fromBuf(&globalGNB_ID->pLMNIdentity, (char*)plmn_enc, 3);

    // Set gNB-ID (22 bits)
    globalGNB_ID->gNB_ID.present = NGAP_GNB_ID_PR_gNB_ID;
    globalGNB_ID->gNB_ID.choice.gNB_ID.size = 3;
    globalGNB_ID->gNB_ID.choice.gNB_ID.buf = calloc(3, sizeof(uint8_t));
    if (!globalGNB_ID->gNB_ID.choice.gNB_ID.buf) return -1;

    uint32_t gnb_id_val = gnb_id & 0x3FFFFF;
    globalGNB_ID->gNB_ID.choice.gNB_ID.buf[0] = (gnb_id_val >> 16) & 0xFF;
    globalGNB_ID->gNB_ID.choice.gNB_ID.buf[1] = (gnb_id_val >> 8) & 0xFF;
    globalGNB_ID->gNB_ID.choice.gNB_ID.buf[2] = gnb_id_val & 0xFF;
    globalGNB_ID->gNB_ID.choice.gNB_ID.bits_unused = 2;

    // 1) GlobalRANNodeID
    ie = calloc(1, sizeof(NGAP_NGSetupRequestIEs_t));
    if (!ie) return -1;
    ASN_SEQUENCE_ADD(&NGSetupRequest->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_GlobalRANNodeID;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_NGSetupRequestIEs__value_PR_GlobalRANNodeID;

    GlobalRANNodeID = &ie->value.choice.GlobalRANNodeID;
    GlobalRANNodeID->present = NGAP_GlobalRANNodeID_PR_globalGNB_ID;
    GlobalRANNodeID->choice.globalGNB_ID = globalGNB_ID;

    // 2) RANNodeName
    ie = calloc(1, sizeof(NGAP_NGSetupRequestIEs_t));
    if (!ie) return -1;
    ASN_SEQUENCE_ADD(&NGSetupRequest->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_RANNodeName;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present = NGAP_NGSetupRequestIEs__value_PR_RANNodeName;

    RANNodeName = &ie->value.choice.RANNodeName;
    OCTET_STRING_fromBuf(RANNodeName, ran_name, strlen(ran_name));

    // 3) SupportedTAList
    ie = calloc(1, sizeof(NGAP_NGSetupRequestIEs_t));
    if (!ie) return -1;
    ASN_SEQUENCE_ADD(&NGSetupRequest->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_SupportedTAList;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_NGSetupRequestIEs__value_PR_SupportedTAList;

    SupportedTAList = &ie->value.choice.SupportedTAList;

    // Create SupportedTAItem
    SupportedTAItem = calloc(1, sizeof(NGAP_SupportedTAItem_t));
    if (!SupportedTAItem) return -1;

    // Set TAC
    SupportedTAItem->tAC.size = 3;
    SupportedTAItem->tAC.buf = calloc(3, sizeof(uint8_t));
    if (!SupportedTAItem->tAC.buf) return -1;

    long tac_val = tac;
    SupportedTAItem->tAC.buf[0] = (tac_val >> 16) & 0xFF;
    SupportedTAItem->tAC.buf[1] = (tac_val >> 8) & 0xFF;
    SupportedTAItem->tAC.buf[2] = tac_val & 0xFF;

    // Create BroadcastPLMNItem
    BroadcastPLMNItem = calloc(1, sizeof(NGAP_BroadcastPLMNItem_t));
    if (!BroadcastPLMNItem) return -1;

    OCTET_STRING_fromBuf(&BroadcastPLMNItem->pLMNIdentity, (char*)plmn_enc, 3);

    // Create SliceSupportItem (sst=1)
    SliceSupportItem = calloc(1, sizeof(NGAP_SliceSupportItem_t));
    if (!SliceSupportItem) return -1;

    SliceSupportItem->s_NSSAI.sST.size = 1;
    SliceSupportItem->s_NSSAI.sST.buf = calloc(1, sizeof(uint8_t));
    if (!SliceSupportItem->s_NSSAI.sST.buf) return -1;
    SliceSupportItem->s_NSSAI.sST.buf[0] = 1; // SST=1

    ASN_SEQUENCE_ADD(&BroadcastPLMNItem->tAISliceSupportList.list, SliceSupportItem);
    ASN_SEQUENCE_ADD(&SupportedTAItem->broadcastPLMNList.list, BroadcastPLMNItem);
    ASN_SEQUENCE_ADD(&SupportedTAList->list, SupportedTAItem);

    // 4) DefaultPagingDRX
    ie = calloc(1, sizeof(NGAP_NGSetupRequestIEs_t));
    if (!ie) return -1;
    ASN_SEQUENCE_ADD(&NGSetupRequest->protocolIEs, ie);

    ie->id = NGAP_ProtocolIE_ID_id_DefaultPagingDRX;
    ie->criticality = NGAP_Criticality_ignore;
    ie->value.present = NGAP_NGSetupRequestIEs__value_PR_PagingDRX;

    PagingDRX = &ie->value.choice.PagingDRX;
    *PagingDRX = NGAP_PagingDRX_v32;

    // Validate constraints for better diagnostics
    char errbuf[256];
    size_t errlen;
    int ccr;

    errlen = sizeof(errbuf);
    ccr = asn_check_constraints(&asn_DEF_NGAP_NGAP_PDU, &pdu, errbuf, &errlen);
    if (ccr) {
        printf("[ERROR] NGAP_PDU constraints: %s\n", errbuf[0]?errbuf:"unknown");
        fflush(stdout);
    }

    errlen = sizeof(errbuf);
    ccr = asn_check_constraints(&asn_DEF_NGAP_NGSetupRequest, NGSetupRequest, errbuf, &errlen);
    if (ccr) {
        printf("[ERROR] NGSetupRequest constraints: %s\n", errbuf[0]?errbuf:"unknown");
        fflush(stdout);
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
    hexdump("NGSetupRequest(dynamic)", buf, out);
    return (int)out;
}

int build_ngsetup_request_args(uint8_t *buf, size_t *len,
    const char *mcc, const char *mnc, long tac, uint32_t gnb_id, const char *ran_name) {
    return build_ngsetup_request_internal(buf, len, mcc, mnc, tac, gnb_id, ran_name);
}

int build_ngsetup_request_dynamic(uint8_t *buf, size_t *len) {
    const char *env_mcc = getenv("S1N2_MCC"); if (!env_mcc||!*env_mcc) env_mcc = getenv("MCC"); if (!env_mcc||!*env_mcc) env_mcc = "001";
    const char *env_mnc = getenv("S1N2_MNC"); if (!env_mnc||!*env_mnc) env_mnc = getenv("MNC"); if (!env_mnc||!*env_mnc) env_mnc = "01";
    const char *env_tac = getenv("S1N2_TAC"); if (!env_tac||!*env_tac) env_tac = getenv("TAC"); if (!env_tac||!*env_tac) env_tac = "1";
    const char *env_name = getenv("S1N2_RAN_NAME"); if (!env_name||!*env_name) env_name = "s1n2-gNB";
    long tac_val = strtol(env_tac, NULL, 10);
    return build_ngsetup_request_internal(buf, len, env_mcc, env_mnc, tac_val, 1, env_name);
}
