#ifndef S1N2_BUILDERS_H
#define S1N2_BUILDERS_H

#include <stdint.h>
#include <stddef.h>

/* Forward-declare ASN.1 types used in builder APIs */
struct NGAP_Cause;
typedef struct NGAP_Cause NGAP_Cause_t;
struct S1AP_Cause;
typedef struct S1AP_Cause S1AP_Cause_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ── S1AP builders ─────────────────────────────────── */

int build_s1ap_initial_context_setup_request(uint8_t *buffer, size_t *buffer_len,
                                             long mme_ue_s1ap_id, long enb_ue_s1ap_id,
                                             const uint8_t *nas_pdu, size_t nas_pdu_len,
                                             uint8_t e_rab_id,
                                             uint32_t s1u_ipv4_be, uint32_t s1u_teid_be,
                                             const uint8_t *kenb);

int build_s1ap_downlink_nas(uint8_t *buffer, size_t *buffer_len,
                            long mme_ue_s1ap_id, long enb_ue_s1ap_id,
                            const uint8_t *nas_pdu, size_t nas_pdu_len);

/* ── NGAP builders ─────────────────────────────────── */

int build_ngap_downlink_nas(uint8_t *buffer, size_t *buffer_len,
                            long amf_ue_ngap_id, long ran_ue_ngap_id,
                            const uint8_t *nas_pdu, size_t nas_pdu_len);

int build_ngap_uplink_nas(uint8_t *buffer, size_t *buffer_len,
                          long amf_ue_ngap_id, long ran_ue_ngap_id,
                          const uint8_t *nas_pdu, size_t nas_pdu_len,
                          const uint8_t *plmn_id, size_t plmn_id_len,
                          uint32_t cell_id, uint16_t tac);

int build_ngap_error_indication(uint8_t *buffer, size_t *buffer_len,
                                long amf_ue_ngap_id, long ran_ue_ngap_id,
                                const NGAP_Cause_t *cause);

int build_ngap_nas_non_delivery(uint8_t *buffer, size_t *buffer_len,
                                long amf_ue_ngap_id, long ran_ue_ngap_id,
                                const uint8_t *nas_pdu, size_t nas_pdu_len,
                                const NGAP_Cause_t *cause);

int build_ngap_ue_context_release_request(uint8_t *buffer, size_t *buffer_len,
                                          long amf_ue_ngap_id, long ran_ue_ngap_id,
                                          const NGAP_Cause_t *cause);

int build_ngap_pdu_session_setup_request(uint8_t *buffer, size_t *buffer_len,
                                         long amf_ue_ngap_id, long ran_ue_ngap_id,
                                         uint8_t pdu_session_id, uint8_t qci,
                                         uint32_t upf_ipv4_be, uint32_t upf_teid_be);

/* ── Cause helpers ─────────────────────────────────── */

void s1n2_copy_s1ap_cause_to_ngap(const S1AP_Cause_t *src, NGAP_Cause_t *dst);
long s1n2_get_s1ap_cause_value(const S1AP_Cause_t *cause);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_BUILDERS_H */
