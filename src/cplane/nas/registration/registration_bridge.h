#ifndef S1N2_REGISTRATION_BRIDGE_H
#define S1N2_REGISTRATION_BRIDGE_H
#include "s1n2_converter.h"
/* 5GS registration completes before EPS attach so the SMF can allocate an IP. */
int s1n2_start_registration_session(s1n2_context_t *ctx, ue_id_mapping_t *ue);
int s1n2_cache_pdu_address(ue_id_mapping_t *ue, const uint8_t *nas, size_t len);
#endif
