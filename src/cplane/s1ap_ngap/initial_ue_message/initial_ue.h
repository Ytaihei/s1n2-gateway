#ifndef S1N2_INITIAL_UE_MESSAGE_H
#define S1N2_INITIAL_UE_MESSAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration (matches s1n2_converter.h typedef)
typedef struct s1n2_context s1n2_context_t;

/**
 * Convert S1AP InitialUEMessage to NGAP InitialUEMessage
 * @param ctx S1N2 context
 * @param s1ap_data S1AP InitialUEMessage
 * @param s1ap_len Length of S1AP message
 * @param ngap_data Output buffer for NGAP InitialUEMessage
 * @param ngap_len Pointer to buffer length (in/out)
 * @return 0 on success, -1 on error
 */
int initial_ue_dispatch_convert(s1n2_context_t *ctx,
                               const uint8_t *s1ap_data,
                               size_t s1ap_len,
                               uint8_t *ngap_data,
                               size_t *ngap_len);

/**
 * Build NGAP InitialUEMessage
 * @param buf Output buffer
 * @param len Pointer to buffer length (in/out)
 * @param ran_ue_ngap_id RAN UE NGAP ID
 * @param nas_pdu NAS PDU data
 * @param nas_pdu_len Length of NAS PDU
 * @param mcc Mobile Country Code (3 digits)
 * @param mnc Mobile Network Code (2-3 digits)
 * @param nr_cell_id NR Cell ID (36 bits)
 * @param tac Tracking Area Code
 * @param include_5g_s_tmsi Include 5G-S-TMSI
 * @param amf_set_id AMF Set ID (10 bits)
 * @param amf_pointer AMF Pointer (6 bits)
 * @param fiveg_tmsi 5G-TMSI
 * @param rrc_cause RRC Establishment Cause
 * @param ue_context_requested UE Context Request flag
 * @return Encoded length on success, -1 on error
 */
int initial_ue_builder_ngap(uint8_t *buf, size_t *len,
                           uint32_t ran_ue_ngap_id,
                           const uint8_t *nas_pdu, size_t nas_pdu_len,
                           const char *mcc, const char *mnc,
                           uint32_t nr_cell_id, long tac,
                           bool include_5g_s_tmsi,
                           uint32_t amf_set_id, uint32_t amf_pointer, uint32_t fiveg_tmsi,
                           uint8_t rrc_cause, bool ue_context_requested);

#ifdef __cplusplus
}
#endif

#endif // S1N2_INITIAL_UE_MESSAGE_H
