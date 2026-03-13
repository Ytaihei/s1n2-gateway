#ifndef S1N2_CONTEXT_INTERNAL_H
#define S1N2_CONTEXT_INTERNAL_H

#include "s1n2_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

s1n2_auth_context_t *s1n2_context_get_shared_auth(void);
ue_id_mapping_t *s1n2_context_find_mapping_by_enb(s1n2_context_t *ctx, long enb_id);
ue_id_mapping_t *s1n2_context_find_mapping_by_ran(s1n2_context_t *ctx, long ran_id);
ue_id_mapping_t *s1n2_context_find_mapping_by_amf(s1n2_context_t *ctx, long amf_id);
ue_id_mapping_t *s1n2_context_find_recent_security(s1n2_context_t *ctx);
ue_id_mapping_t *s1n2_context_find_mapping_with_cached_rand(s1n2_context_t *ctx);
ue_id_mapping_t *s1n2_context_create_mapping(s1n2_context_t *ctx,
                                             long ran_id,
                                             long amf_id,
                                             long enb_id,
                                             long mme_id);
ue_id_mapping_t *s1n2_context_ensure_mapping_for_enb(s1n2_context_t *ctx, long enb_id);
long s1n2_context_generate_ran_ue_ngap_id(s1n2_context_t *ctx, long preferred_id);

void s1n2_context_mark_tau_start(ue_id_mapping_t *ue_map);
void s1n2_context_mark_tau_complete(ue_id_mapping_t *ue_map);
void s1n2_context_trace_tau_flags(const ue_id_mapping_t *ue_map, const char *label);
void s1n2_context_maybe_timeout_tau(ue_id_mapping_t *ue_map, const char *trigger);
bool s1n2_context_should_preserve_teid(const ue_id_mapping_t *ue_map);
void s1n2_context_cache_registration_result(ue_id_mapping_t *ue_map,
                                            const uint8_t *value,
                                            uint8_t len);
void s1n2_context_cache_5g_guti(ue_id_mapping_t *ue_map,
                                const uint8_t *value,
                                uint16_t len);
void s1n2_context_cache_access_type(ue_id_mapping_t *ue_map,
                                    uint8_t access_type);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_CONTEXT_INTERNAL_H */
