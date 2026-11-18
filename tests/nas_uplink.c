/* Exercise real S1AP decode, EPS NAS verification/decryption and NGAP encode. */
#include <assert.h>
#include "internal/s1n2_converter_internal.h"

static size_t encode_transport(const uint8_t *nas, size_t nas_len, uint8_t *out, size_t cap) {
    S1AP_S1AP_PDU_t pdu = {0};
    pdu.present = S1AP_S1AP_PDU_PR_initiatingMessage;
    pdu.choice.initiatingMessage = calloc(1, sizeof(*pdu.choice.initiatingMessage));
    assert(pdu.choice.initiatingMessage);
    S1AP_InitiatingMessage_t *init = pdu.choice.initiatingMessage;
    init->procedureCode = S1AP_ProcedureCode_id_uplinkNASTransport;
    init->criticality = S1AP_Criticality_ignore;
    init->value.present = S1AP_InitiatingMessage__value_PR_UplinkNASTransport;
    S1AP_UplinkNASTransport_t *msg = &init->value.choice.UplinkNASTransport;
    S1AP_UplinkNASTransport_IEs_t *mme = calloc(1,sizeof(*mme));
    S1AP_UplinkNASTransport_IEs_t *enb = calloc(1,sizeof(*enb));
    S1AP_UplinkNASTransport_IEs_t *payload = calloc(1,sizeof(*payload));
    assert(mme && enb && payload);
    mme->id = S1AP_ProtocolIE_ID_id_MME_UE_S1AP_ID;
    mme->value.present = S1AP_UplinkNASTransport_IEs__value_PR_MME_UE_S1AP_ID;
    mme->value.choice.MME_UE_S1AP_ID = 1;
    enb->id = S1AP_ProtocolIE_ID_id_eNB_UE_S1AP_ID;
    enb->value.present = S1AP_UplinkNASTransport_IEs__value_PR_ENB_UE_S1AP_ID;
    enb->value.choice.ENB_UE_S1AP_ID = 1;
    payload->id = S1AP_ProtocolIE_ID_id_NAS_PDU;
    payload->value.present = S1AP_UplinkNASTransport_IEs__value_PR_NAS_PDU;
    assert(OCTET_STRING_fromBuf(&payload->value.choice.NAS_PDU, (const char *)nas, nas_len) == 0);
    assert(ASN_SEQUENCE_ADD(&msg->protocolIEs.list, mme) == 0);
    assert(ASN_SEQUENCE_ADD(&msg->protocolIEs.list, enb) == 0);
    assert(ASN_SEQUENCE_ADD(&msg->protocolIEs.list, payload) == 0);
    asn_enc_rval_t er = aper_encode_to_buffer(&asn_DEF_S1AP_S1AP_PDU, NULL, &pdu, out, cap);
    assert(er.encoded > 0);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_S1AP_PDU, &pdu);
    return (er.encoded + 7) / 8;
}

static void run_case(uint8_t selected, s1n2_nas_encryption_alg_t encryption) {
    s1n2_context_t *ctx = calloc(1, sizeof(*ctx));
    assert(ctx);
    ctx->num_ue_mappings = 1;
    ue_id_mapping_t *ue = &ctx->ue_mappings[0];
    ue->in_use = ue->has_security_mode = ue->has_nas_keys = true;
    ue->enb_ue_s1ap_id = ue->mme_ue_s1ap_id = ue->ran_ue_ngap_id = ue->amf_ue_ngap_id = 1;
    ue->selected_nas_security_alg = selected;
    /* Synthetic zero keys are sufficient for this packet-processing fixture. */
    uint8_t nas[8] = {0x47,0,0,0,0,0,7,0x5e};
    uint8_t plain[] = {7,0x5e};
    assert(s1n2_nas_encrypt(encryption, ue->k_nas_enc, 0, 0, 0,
                           plain, sizeof(plain), nas + 6) == 0);
    assert(s1n2_nas_compute_mac(S1N2_NAS_EIA2, ue->k_nas_int, 0, 0, 0,
                              nas + 5, 3, nas + 1) == 0);
    uint8_t s1ap[2048], ngap[2048];
    size_t s1ap_len = encode_transport(nas, sizeof(nas), s1ap, sizeof(s1ap));
    size_t ngap_len = sizeof(ngap);
    assert(s1n2_convert_uplink_nas_transport(ctx, s1ap, s1ap_len, ngap, &ngap_len) == 0);
    NGAP_NGAP_PDU_t *pdu = NULL;
    asn_dec_rval_t dr = aper_decode_complete(NULL, &asn_DEF_NGAP_NGAP_PDU,
                                            (void **)&pdu, ngap, ngap_len);
    assert(dr.code == RC_OK && pdu);
    assert(pdu->present == NGAP_NGAP_PDU_PR_initiatingMessage);
    assert(pdu->choice.initiatingMessage->value.present == NGAP_InitiatingMessage__value_PR_UplinkNASTransport);
    NGAP_UplinkNASTransport_t *msg = &pdu->choice.initiatingMessage->value.choice.UplinkNASTransport;
    bool found = false;
    for (int i=0; i<msg->protocolIEs.list.count; i++) {
        NGAP_UplinkNASTransport_IEs_t *ie = msg->protocolIEs.list.array[i];
        if (ie->id == NGAP_ProtocolIE_ID_id_NAS_PDU) {
            const uint8_t expected[] = {0x7e,0,0x5e};
            assert(ie->value.choice.NAS_PDU.size >= sizeof(expected));
            assert(memcmp(ie->value.choice.NAS_PDU.buf, expected, sizeof(expected)) == 0);
            found = true;
        }
    }
    assert(found);
    ASN_STRUCT_FREE(asn_DEF_NGAP_NGAP_PDU, pdu);
    nas[1] ^= 1; /* EEA0 must still enforce the independently selected EIA2. */
    s1ap_len = encode_transport(nas, sizeof(nas), s1ap, sizeof(s1ap));
    ngap_len = sizeof(ngap);
    assert(s1n2_convert_uplink_nas_transport(ctx, s1ap, s1ap_len, ngap, &ngap_len) == -1);
    free(ctx);
}

int main(void) {
    run_case(0x02, S1N2_NAS_EEA0);
    run_case(0x22, S1N2_NAS_EEA2);
    puts("PASS: S1AP uplink NAS EEA0/EEA2 with EIA2, including bad MAC rejection");
    return 0;
}
