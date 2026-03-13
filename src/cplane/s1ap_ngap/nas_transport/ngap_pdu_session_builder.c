/**
 * @file ngap_pdu_session_builder.c
 * @brief NGAP PDUSessionResourceSetupRequest ASN.1 encoder
 *
 * Wireshark trace: NGAP PDUSessionResourceSetupRequest
 *
 * Moved from src/cplane/protocol_builders.c — Phase 4 refactoring.
 * Public API preserved in include/internal/protocol_builders.h.
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

/* NGAP headers */
#include "NGAP_NGAP-PDU.h"
#include "NGAP_InitiatingMessage.h"
#include "NGAP_ProtocolIE-Field.h"
#include "NGAP_ProtocolIE-ID.h"
#include "NGAP_Criticality.h"
#include "NGAP_AMF-UE-NGAP-ID.h"
#include "NGAP_RAN-UE-NGAP-ID.h"
#include "NGAP_ProcedureCode.h"
#include "NGAP_UPTransportLayerInformation.h"
#include "NGAP_GTPTunnel.h"
#include "NGAP_TransportLayerAddress.h"
#include "NGAP_GTP-TEID.h"
#include "NGAP_PDUSessionResourceSetupRequest.h"
#include "NGAP_PDUSessionResourceSetupListSUReq.h"
#include "NGAP_PDUSessionResourceSetupItemSUReq.h"
#include "NGAP_PDUSessionResourceSetupRequestTransfer.h"
#include "NGAP_PDUSessionType.h"
#include "NGAP_QosFlowSetupRequestList.h"
#include "NGAP_QosFlowSetupRequestItem.h"
#include "NGAP_QosCharacteristics.h"
#include "NGAP_NonDynamic5QIDescriptor.h"
#include "NGAP_FiveQI.h"

int build_ngap_pdu_session_setup_request(uint8_t *buffer, size_t *buffer_len,
                                         long amf_ue_ngap_id, long ran_ue_ngap_id,
                                         uint8_t pdu_session_id, uint8_t qci,
                                         uint32_t upf_ipv4_be, uint32_t upf_teid_be) {
    if (!buffer || !buffer_len || *buffer_len < 512) {
        return -1;
    }

    printf("[INFO] Building NGAP PDUSessionResourceSetupRequest: PDU Session ID=%u, QCI/QFI=%u\n",
           pdu_session_id, qci);
    printf("[INFO]   UPF: IP=%s, TEID=0x%08x\n",
           inet_ntoa(*(struct in_addr *)&upf_ipv4_be), ntohl(upf_teid_be));

    NGAP_PDUSessionResourceSetupRequestTransfer_t transfer_msg;
    memset(&transfer_msg, 0, sizeof(transfer_msg));

    /* IE 1: UL-NGU-UP-TNLInformation (mandatory) */
    NGAP_PDUSessionResourceSetupRequestTransferIEs_t *ie =
        calloc(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    if (!ie) {
        printf("[ERROR] Failed to allocate IE for UL-NGU-UP-TNLInformation\n");
        return -1;
    }
    ie->id = NGAP_ProtocolIE_ID_id_UL_NGU_UP_TNLInformation;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_UPTransportLayerInformation;

    NGAP_UPTransportLayerInformation_t *uplink_tnl = &ie->value.choice.UPTransportLayerInformation;
    uplink_tnl->present = NGAP_UPTransportLayerInformation_PR_gTPTunnel;
    uplink_tnl->choice.gTPTunnel = calloc(1, sizeof(NGAP_GTPTunnel_t));
    if (!uplink_tnl->choice.gTPTunnel) {
        free(ie);
        printf("[ERROR] Failed to allocate GTPTunnel\n");
        return -1;
    }

    NGAP_GTPTunnel_t *gtp = uplink_tnl->choice.gTPTunnel;
    gtp->transportLayerAddress.buf = calloc(1, 4);
    if (!gtp->transportLayerAddress.buf) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransferIEs, ie);
        free(ie);
        return -1;
    }
    memcpy(gtp->transportLayerAddress.buf, &upf_ipv4_be, 4);
    gtp->transportLayerAddress.size = 4;
    gtp->transportLayerAddress.bits_unused = 0;

    if (OCTET_STRING_fromBuf(&gtp->gTP_TEID, (const char *)&upf_teid_be, 4) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransferIEs, ie);
        free(ie);
        return -1;
    }

    ASN_SEQUENCE_ADD(&transfer_msg.protocolIEs, ie);

    /* IE 2: PDUSessionType (mandatory) */
    ie = calloc(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    if (!ie) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }
    ie->id = NGAP_ProtocolIE_ID_id_PDUSessionType;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_PDUSessionType;
    ie->value.choice.PDUSessionType = NGAP_PDUSessionType_ipv4;
    ASN_SEQUENCE_ADD(&transfer_msg.protocolIEs, ie);

    /* IE 3: QoSFlowSetupRequestList (mandatory) */
    ie = calloc(1, sizeof(NGAP_PDUSessionResourceSetupRequestTransferIEs_t));
    if (!ie) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }
    ie->id = NGAP_ProtocolIE_ID_id_QosFlowSetupRequestList;
    ie->criticality = NGAP_Criticality_reject;
    ie->value.present = NGAP_PDUSessionResourceSetupRequestTransferIEs__value_PR_QosFlowSetupRequestList;

    NGAP_QosFlowSetupRequestList_t *qos_list = &ie->value.choice.QosFlowSetupRequestList;
    NGAP_QosFlowSetupRequestItem_t *qos_item = calloc(1, sizeof(NGAP_QosFlowSetupRequestItem_t));
    if (!qos_item) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransferIEs, ie);
        free(ie);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }

    qos_item->qosFlowIdentifier = (qci > 0 && qci <= 9) ? qci : 9;
    qos_item->qosFlowLevelQosParameters.qosCharacteristics.present =
        NGAP_QosCharacteristics_PR_nonDynamic5QI;
    qos_item->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI =
        calloc(1, sizeof(NGAP_NonDynamic5QIDescriptor_t));
    if (!qos_item->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI) {
        free(qos_item);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransferIEs, ie);
        free(ie);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }
    qos_item->qosFlowLevelQosParameters.qosCharacteristics.choice.nonDynamic5QI->fiveQI =
        (qci > 0 && qci <= 9) ? qci : 9;

    qos_item->qosFlowLevelQosParameters.allocationAndRetentionPriority.priorityLevelARP = 1;
    qos_item->qosFlowLevelQosParameters.allocationAndRetentionPriority.pre_emptionCapability =
        NGAP_Pre_emptionCapability_shall_not_trigger_pre_emption;
    qos_item->qosFlowLevelQosParameters.allocationAndRetentionPriority.pre_emptionVulnerability =
        NGAP_Pre_emptionVulnerability_not_pre_emptable;

    ASN_SEQUENCE_ADD(&qos_list->list, qos_item);
    ASN_SEQUENCE_ADD(&transfer_msg.protocolIEs, ie);

    /* Encode PDUSessionResourceSetupRequestTransfer */
    void *transfer_buf = NULL;
    ssize_t transfer_bytes = aper_encode_to_new_buffer(&asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer,
                                                       NULL, &transfer_msg, &transfer_buf);
    if (transfer_bytes <= 0 || !transfer_buf) {
        printf("[ERROR] Failed to encode PDUSessionResourceSetupRequestTransfer\n");
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }

    printf("[INFO] Encoded PDUSessionResourceSetupRequestTransfer: %zd bytes\n", transfer_bytes);

    /* Build main NGAP PDU */
    NGAP_NGAP_PDU_t *pdu = calloc(1, sizeof(NGAP_NGAP_PDU_t));
    if (!pdu) {
        free(transfer_buf);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        return -1;
    }

    pdu->present = NGAP_NGAP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(NGAP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage) {
        free(transfer_buf);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
        ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
        return -1;
    }

    NGAP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = NGAP_ProcedureCode_id_PDUSessionResourceSetup;
    init->criticality = NGAP_Criticality_reject;
    init->value.present = NGAP_InitiatingMessage__value_PR_PDUSessionResourceSetupRequest;

    NGAP_PDUSessionResourceSetupRequest_t *req = &init->value.choice.PDUSessionResourceSetupRequest;

    NGAP_PDUSessionResourceSetupRequestIEs_t *req_ie = calloc(1, sizeof(*req_ie));
    if (!req_ie) goto fail;
    req_ie->id = NGAP_ProtocolIE_ID_id_AMF_UE_NGAP_ID;
    req_ie->criticality = NGAP_Criticality_reject;
    req_ie->value.present = NGAP_PDUSessionResourceSetupRequestIEs__value_PR_AMF_UE_NGAP_ID;
    if (asn_long2INTEGER(&req_ie->value.choice.AMF_UE_NGAP_ID, amf_ue_ngap_id) != 0) {
        free(req_ie);
        goto fail;
    }
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, req_ie);

    req_ie = calloc(1, sizeof(*req_ie));
    if (!req_ie) goto fail;
    req_ie->id = NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID;
    req_ie->criticality = NGAP_Criticality_reject;
    req_ie->value.present = NGAP_PDUSessionResourceSetupRequestIEs__value_PR_RAN_UE_NGAP_ID;
    req_ie->value.choice.RAN_UE_NGAP_ID = ran_ue_ngap_id;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, req_ie);

    req_ie = calloc(1, sizeof(*req_ie));
    if (!req_ie) goto fail;
    req_ie->id = NGAP_ProtocolIE_ID_id_PDUSessionResourceSetupListSUReq;
    req_ie->criticality = NGAP_Criticality_reject;
    req_ie->value.present = NGAP_PDUSessionResourceSetupRequestIEs__value_PR_PDUSessionResourceSetupListSUReq;

    NGAP_PDUSessionResourceSetupListSUReq_t *setup_list = &req_ie->value.choice.PDUSessionResourceSetupListSUReq;

    NGAP_PDUSessionResourceSetupItemSUReq_t *item = calloc(1, sizeof(*item));
    if (!item) { free(req_ie); goto fail; }

    item->pDUSessionID = pdu_session_id;

    item->s_NSSAI.sST.buf = calloc(1, 1);
    if (!item->s_NSSAI.sST.buf) { free(item); free(req_ie); goto fail; }
    item->s_NSSAI.sST.buf[0] = 0x01;
    item->s_NSSAI.sST.size = 1;

    if (OCTET_STRING_fromBuf(&item->pDUSessionResourceSetupRequestTransfer,
                             (const char *)transfer_buf, (size_t)transfer_bytes) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupItemSUReq, item);
        free(item);
        free(req_ie);
        goto fail;
    }

    ASN_SEQUENCE_ADD(&setup_list->list, item);
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, req_ie);

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_NGAP_PDUSessionResourceSetupRequestTransfer, &transfer_msg);
    free(transfer_buf);

    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_NGAP_NGAP_PDU, NULL, pdu, buffer, *buffer_len);
    if (er.encoded == -1) {
        printf("[ERROR] Failed to encode NGAP PDUSessionResourceSetupRequest: %s\n",
               er.failed_type ? er.failed_type->name : "unknown");
        goto fail;
    }

    size_t bytes = (er.encoded + 7) / 8;
    if (bytes > *buffer_len) {
        printf("[ERROR] NGAP PDUSessionResourceSetupRequest too large: %zu > %zu\n", bytes, *buffer_len);
        goto fail;
    }
    *buffer_len = bytes;

    printf("[INFO] Successfully built NGAP PDUSessionResourceSetupRequest (%zu bytes)\n", bytes);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return 0;

fail:
    printf("[ERROR] Failed to build NGAP PDUSessionResourceSetupRequest\n");
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    return -1;
}
