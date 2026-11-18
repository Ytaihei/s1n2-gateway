#include "internal/s1n2_converter_internal.h"
#include "registration/registration.h"
#include "registration_bridge.h"
#include "internal/nas_module_common.h"
#include "s1n2_log.h"

static int send_uplink(s1n2_context_t *ctx, ue_id_mapping_t *ue,
                       const uint8_t *nas, size_t len) {
    uint8_t ngap[2048];
    size_t ngap_len = sizeof(ngap);
    if (build_ngap_uplink_nas(ngap, &ngap_len, ue->amf_ue_ngap_id, ue->ran_ue_ngap_id,
        nas, len, ue->plmn_id, ue->plmn_id_len, ue->cell_id, ue->tac) != 0) return -1;
    return sctp_sendmsg(ctx->n2_fd, ngap, ngap_len, NULL, 0, htonl(60), 0, 0, 0, 0)
        == (ssize_t)ngap_len ? 0 : -1;
}

int s1n2_start_registration_session(s1n2_context_t *ctx, ue_id_mapping_t *ue) {
    if (!ctx || !ue || !ue->pending_registration_accept_len || !ue->has_5g_nas_keys) return -1;
    uint8_t nas[1024];
    size_t len = sizeof(nas);
    if (!ue->registration_complete_sent) {
        if (attach_complete_convert_4g_to_5g(nas, &len, ue) != 0 ||
            send_uplink(ctx, ue, nas, len) != 0) return -1;
        ue->registration_complete_sent = true;
    }
    if (ue->pdu_session_requested) return 0;
    ue->pdu_session_id = 5;
    ue->ics_e_rab_id = 5;
    ue->qci = ue->qfi = 9;
    s1n2_get_apn_from_env(ue->apn, sizeof(ue->apn));
    len = sizeof(nas);
    if (build_gmm_ul_nas_transport_with_n1_sm(nas, &len, ue, ue->pdu_session_id,
        ue->apn, 1, 1) != 0 || send_uplink(ctx, ue, nas, len) != 0) return -1;
    ue->pdu_session_requested = true;
    ue->send_pdu_session_establishment = false;
    LOG_INFO("Registration complete sent; waiting for core-assigned PDU address");
    return 0;
}

int s1n2_cache_pdu_address(ue_id_mapping_t *ue, const uint8_t *nas, size_t len) {
    if (!ue || !nas || len < 6 || nas[0] != 0x7e || nas[1] != 0 ||
        nas[2] != 0x68 || (nas[3] & 0x0f) != 1) return -1;
    size_t payload_len = ((size_t)nas[4] << 8) | nas[5];
    if (payload_len > len - 6 || payload_len < 8) return -1;
    const uint8_t *sm = nas + 6;
    if (sm[0] != 0x2e || sm[1] != ue->pdu_session_id || sm[3] != 0xc2) return -1;
    /* Header, selected session/SSC type, QoS rules (LV-E), session AMBR (LV). */
    size_t pos = 5;
    size_t qos_len = ((size_t)sm[pos] << 8) | sm[pos+1];
    pos += 2;
    if (qos_len > payload_len - pos) return -1;
    pos += qos_len;
    if (pos >= payload_len) return -1;
    size_t ambr_len = sm[pos++];
    if (ambr_len > payload_len - pos) return -1;
    pos += ambr_len;
    uint8_t address[4];
    bool found = false;
    while (pos < payload_len) {
        uint8_t ie = sm[pos++];
        if (ie >= 0x80) continue; /* Type 1 TV: one octet. */
        if (ie == 0x59 || ie == 0x56) { /* 5GSM cause / timer: TV. */
            if (pos >= payload_len) return -1;
            pos++; continue;
        }
        size_t length_octets;
        switch (ie) {
            case 0x29: case 0x22: case 0x25: case 0x17: case 0x18:
            case 0x66: case 0x1f: length_octets = 1; break;
            case 0x75: case 0x78: case 0x79: case 0x7b: case 0x77:
            case 0x72: case 0x71: length_octets = 2; break;
            default: return -1; /* Do not search arbitrary payload bytes for an IE. */
        }
        if (length_octets > payload_len - pos) return -1;
        size_t n = sm[pos++];
        if (length_octets == 2) n = (n << 8) | sm[pos++];
        if (n > payload_len - pos) return -1;
        if (ie == 0x29) {
            if (found || n < 1) return -1;
            uint8_t type = sm[pos] & 7;
            if (!((type == 1 && n == 5) || (type == 3 && n == 13))) return -1;
            memcpy(address, sm + pos + n - 4, 4);
            found = true;
        }
        pos += n;
    }
    if (!found) return -1;
    memcpy(ue->pdu_ipv4, address, sizeof(address));
    ue->has_pdu_ipv4 = true;
    LOG_INFO("Core-assigned IPv4 address cached for PDU session %u", ue->pdu_session_id);
    return 0;
}
