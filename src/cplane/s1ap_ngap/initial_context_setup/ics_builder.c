/**
 * @file ics_builder.c
 * @brief S1AP InitialContextSetupRequest ASN.1 encoder
 *
 * Wireshark trace: S1AP InitialContextSetupRequest
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

/* S1AP headers */
#include "S1AP_S1AP-PDU.h"
#include "S1AP_InitiatingMessage.h"
#include "S1AP_ProtocolIE-Field.h"
#include "S1AP_ProtocolIE-ID.h"
#include "S1AP_ProtocolIE-SingleContainer.h"
#include "S1AP_NAS-PDU.h"
#include "S1AP_UEAggregateMaximumBitrate.h"
#include "S1AP_E-RABToBeSetupItemCtxtSUReq.h"
#include "S1AP_E-RABToBeSetupListCtxtSUReq.h"
#include "S1AP_InitialContextSetupRequest.h"
#include "S1AP_E-RABLevelQoSParameters.h"
#include "S1AP_AllocationAndRetentionPriority.h"
#include "S1AP_Cause.h"
#include "S1AP_TransportLayerAddress.h"
#include "S1AP_GTP-TEID.h"
#include "S1AP_UESecurityCapabilities.h"
#include "S1AP_SecurityKey.h"
#include "S1AP_ProcedureCode.h"

int build_s1ap_initial_context_setup_request(uint8_t *buffer, size_t *buffer_len,
                                             long mme_ue_s1ap_id, long enb_ue_s1ap_id,
                                             const uint8_t *nas_pdu, size_t nas_pdu_len,
                                             uint8_t e_rab_id,
                                             uint32_t s1u_ipv4_be, uint32_t s1u_teid_be,
                                             const uint8_t *kenb) {
    if (!buffer || !buffer_len) return -1;

    S1AP_S1AP_PDU_t *pdu = calloc(1, sizeof(S1AP_S1AP_PDU_t));
    if (!pdu) return -1;

    pdu->present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = calloc(1, sizeof(S1AP_InitiatingMessage_t));
    if (!pdu->choice.initiatingMessage) goto fail;

    S1AP_InitiatingMessage_t *init = pdu->choice.initiatingMessage;
    init->procedureCode = S1AP_ProcedureCode_id_InitialContextSetup;
    init->criticality = S1AP_Criticality_reject;
    init->value.present = S1AP_InitiatingMessage__value_PR_InitialContextSetupRequest;

    S1AP_InitialContextSetupRequest_t *req = &init->value.choice.InitialContextSetupRequest;

    /* MME_UE_S1AP_ID */
    S1AP_InitialContextSetupRequestIEs_t *ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_MME_UE_S1AP_ID;
    ie->value.choice.MME_UE_S1AP_ID = (unsigned long)mme_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    /* eNB_UE_S1AP_ID */
    ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_ENB_UE_S1AP_ID;
    ie->value.choice.ENB_UE_S1AP_ID = (long)enb_ue_s1ap_id;
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    /* UE Aggregate Maximum Bitrate (mandatory) */
    ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_uEaggregateMaximumBitrate;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UEAggregateMaximumBitrate;
    {
        S1AP_UEAggregateMaximumBitrate_t *ambr = &ie->value.choice.UEAggregateMaximumBitrate;
        long dl = 100000000;
        long ul = 100000000;
        asn_long2INTEGER(&ambr->uEaggregateMaximumBitRateDL, dl);
        asn_long2INTEGER(&ambr->uEaggregateMaximumBitRateUL, ul);
    }
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    /* E-RABToBeSetupListCtxtSUReq with one default bearer (QCI 9) */
    ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupListCtxtSUReq;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_E_RABToBeSetupListCtxtSUReq;
    S1AP_E_RABToBeSetupListCtxtSUReq_t *lst = &ie->value.choice.E_RABToBeSetupListCtxtSUReq;

    S1AP_ProtocolIE_SingleContainer_8146P5_t *sc = calloc(1, sizeof(*sc));
    if (!sc) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_InitialContextSetupRequestIEs, ie);
        free(ie);
        goto fail;
    }
    sc->id = S1AP_ProtocolIE_ID_id_E_RABToBeSetupItemCtxtSUReq;
    sc->criticality = S1AP_Criticality_reject;
    sc->value.present = S1AP_E_RABToBeSetupItemCtxtSUReqIEs__value_PR_E_RABToBeSetupItemCtxtSUReq;

    S1AP_E_RABToBeSetupItemCtxtSUReq_t *item = &sc->value.choice.E_RABToBeSetupItemCtxtSUReq;
    item->e_RAB_ID = e_rab_id;

    item->e_RABlevelQoSParameters.qCI = 9;
    S1AP_AllocationAndRetentionPriority_t *arp = &item->e_RABlevelQoSParameters.allocationRetentionPriority;
    arp->priorityLevel = 15;
    arp->pre_emptionCapability = S1AP_Pre_emptionCapability_may_trigger_pre_emption;
    arp->pre_emptionVulnerability = S1AP_Pre_emptionVulnerability_not_pre_emptable;

    item->transportLayerAddress.buf = calloc(1, 4);
    if (!item->transportLayerAddress.buf) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_InitialContextSetupRequestIEs, ie);
        free(ie);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_ProtocolIE_SingleContainer_8146P5, sc);
        free(sc);
        goto fail;
    }
    memcpy(item->transportLayerAddress.buf, &s1u_ipv4_be, 4);
    item->transportLayerAddress.size = 4;
    item->transportLayerAddress.bits_unused = 0;

    if (OCTET_STRING_fromBuf(&item->gTP_TEID, (const char*)&s1u_teid_be, 4) != 0) {
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_InitialContextSetupRequestIEs, ie);
        free(ie);
        ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_ProtocolIE_SingleContainer_8146P5, sc);
        free(sc);
        goto fail;
    }

    if (nas_pdu && nas_pdu_len > 0) {
        item->nAS_PDU = calloc(1, sizeof(S1AP_NAS_PDU_t));
        if (!item->nAS_PDU) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_InitialContextSetupRequestIEs, ie);
            free(ie);
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_ProtocolIE_SingleContainer_8146P5, sc);
            free(sc);
            goto fail;
        }
        if (OCTET_STRING_fromBuf(item->nAS_PDU, (const char*)nas_pdu, nas_pdu_len) != 0) {
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_InitialContextSetupRequestIEs, ie);
            free(ie);
            ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_ProtocolIE_SingleContainer_8146P5, sc);
            free(sc);
            goto fail;
        }
    }

    ASN_SEQUENCE_ADD(&lst->list, sc);
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    /* UE Security Capabilities (mandatory) */
    ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_UESecurityCapabilities;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_UESecurityCapabilities;
    {
        S1AP_UESecurityCapabilities_t *caps = &ie->value.choice.UESecurityCapabilities;
        caps->encryptionAlgorithms.buf = calloc(1, 2);
        if (!caps->encryptionAlgorithms.buf) goto fail;
        caps->encryptionAlgorithms.size = 2;
        caps->encryptionAlgorithms.bits_unused = 0;
        caps->encryptionAlgorithms.buf[0] = 0xE0;
        caps->encryptionAlgorithms.buf[1] = 0x00;

        caps->integrityProtectionAlgorithms.buf = calloc(1, 2);
        if (!caps->integrityProtectionAlgorithms.buf) goto fail;
        caps->integrityProtectionAlgorithms.size = 2;
        caps->integrityProtectionAlgorithms.bits_unused = 0;
        caps->integrityProtectionAlgorithms.buf[0] = 0xE0;
        caps->integrityProtectionAlgorithms.buf[1] = 0x00;
    }
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    /* SecurityKey (mandatory) – 256-bit BIT STRING */
    ie = calloc(1, sizeof(*ie));
    if (!ie) goto fail;
    ie->id = S1AP_ProtocolIE_ID_id_SecurityKey;
    ie->criticality = S1AP_Criticality_reject;
    ie->value.present = S1AP_InitialContextSetupRequestIEs__value_PR_SecurityKey;
    {
        BIT_STRING_t *sk = &ie->value.choice.SecurityKey;
        sk->buf = calloc(1, 32);
        if (!sk->buf) goto fail;
        sk->size = 32;
        sk->bits_unused = 0;

        if (kenb) {
            memcpy(sk->buf, kenb, 32);
            printf("[DEBUG] ICS Request: Using derived KeNB (first 8): ");
            for (int i = 0; i < 8; i++) printf("%02X", kenb[i]);
            printf("..\n");
        } else {
            printf("[WARN] ICS Request: KeNB not provided, using dummy pattern\n");
            for (int i = 0; i < 32; i++) sk->buf[i] = (uint8_t)(0x11 + (i & 0x0F));
        }
    }
    ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie);

    if (asn_check_constraints(&asn_DEF_S1AP_S1AP_PDU, pdu, NULL, NULL) != 0) {
        fprintf(stderr, "[ERROR] ASN.1 constraint check failed for S1AP ICS PDU\n");
        goto fail;
    }

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
