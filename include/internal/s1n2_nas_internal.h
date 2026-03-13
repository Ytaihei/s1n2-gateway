#ifndef S1N2_NAS_INTERNAL_H
#define S1N2_NAS_INTERNAL_H

#include "s1n2_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

int convert_4g_nas_to_5g(s1n2_context_t *ctx,
                         ue_id_mapping_t *ue_map,
                         uint8_t *nas_4g,
                         size_t nas_4g_len,
                         uint8_t *nas_5g,
                         size_t *nas_5g_len);
int convert_5g_nas_to_4g(const uint8_t *nas_5g,
                         size_t nas_5g_len,
                         uint8_t *nas_4g,
                         size_t *nas_4g_len,
                         s1n2_security_mode_info_t *info,
                         ue_id_mapping_t *security_cache);
int s1n2_extract_rand_autn_from_5g_auth_request(const uint8_t *nas_pdu,
                                                size_t nas_len,
                                                uint8_t *rand_out,
                                                uint8_t *autn_out,
                                                uint8_t *sqn_xor_ak_out,
                                                ue_id_mapping_t *ue_map);
int s1n2_extract_imsi_from_5g_registration_request(const uint8_t *nas_pdu,
                                                   size_t nas_len,
                                                   char *imsi_out,
                                                   size_t imsi_len);
int build_pdu_session_establishment_request(uint8_t *nas_5g,
                                            size_t *nas_5g_len,
                                            ue_id_mapping_t *ue_map,
                                            uint8_t pdu_session_id,
                                            const char *dnn,
                                            uint8_t sst);

int build_gmm_ul_nas_transport_with_n1_sm(uint8_t *nas_5g,
                                           size_t *nas_5g_len,
                                           ue_id_mapping_t *ue_map,
                                           uint8_t pdu_session_id,
                                           const char *dnn,
                                           uint8_t sst,
                                           uint8_t request_type);
int s1n2_build_tau_accept_nas(s1n2_context_t *ctx,
                              ue_id_mapping_t *ue_map,
                              uint8_t eps_update_type_octet,
                              uint8_t *out,
                              size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_NAS_INTERNAL_H */
