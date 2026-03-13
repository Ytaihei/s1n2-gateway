/**
 * @file include/internal/nas_module_common.h
 * @brief Common includes and declarations for NAS modules
 *
 * Provides shared include directives and function declarations for all NAS
 * module files (registration, tau, auth, security, pdu_session, shared).
 *
 * Created during Phase 1 refactoring.
 */
#ifndef S1N2_NAS_MODULE_COMMON_H
#define S1N2_NAS_MODULE_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "suci_utils.h"

/* ================================================================
 * Shared module function declarations
 * ================================================================ */

/* --- shared/nas_logging.c --- */
void s1n2_dump_hex(const char *tag, const uint8_t *buf, size_t len);
void s1n2_log_pco_entries(const char *tag, const uint8_t *pco, size_t pco_len);
void s1n2_log_security_mode_result(const char *direction,
								   bool success,
								   uint8_t pd,
								   uint8_t msg_type,
								   const char *details);

/* --- shared/nas_plmn.c --- */
void s1n2_copy_digits(const char *src, char *dst, size_t dst_len);
void s1n2_init_suci_config(suci_builder_config_t *cfg);
void s1n2_get_mcc_mnc_from_env(char out_mcc[4], char out_mnc[4], int *out_mnc_len);
void s1n2_encode_plmn_tbcd(const char mcc[4], const char mnc[4], int mnc_len, uint8_t plmn_out[3]);
uint16_t s1n2_get_tac_from_env(void);

/* --- shared/nas_apn.c --- */
size_t s1n2_safe_strnlen(const char *text, size_t max_len);
size_t s1n2_get_apn_from_env(char *apn_buf, size_t apn_buf_len);
size_t s1n2_encode_apn_label(const char *apn_str, uint8_t *out, size_t out_cap);

/* --- tau/tau_helpers.c --- */
uint8_t s1n2_map_eps_update_type(uint8_t eps_update_type);
uint8_t s1n2_map_eps_update_type_to_update_ie(uint8_t eps_update_type);
uint8_t s1n2_build_registration_type_octet(uint8_t reg_value,
					   uint8_t follow_on_request,
					   const ue_id_mapping_t *ue_map);
int s1n2_append_update_type(uint8_t *nas,
			    size_t *offset,
			    size_t capacity,
			    uint8_t value);
int s1n2_append_last_visited_tai(uint8_t *nas,
				 size_t *offset,
				 size_t capacity,
				 const ue_id_mapping_t *ue_map);

/* --- auth/ module (Phase 2) --- */
/* Public API declared in auth/auth.h */
int auth_request_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
				  uint8_t *nas_4g, size_t *nas_4g_len);
int auth_response_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
				   size_t payload_offset,
				   uint8_t *nas_5g, size_t *nas_5g_len,
				   s1n2_context_t *ctx, ue_id_mapping_t *ue_map);
int auth_failure_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
				  size_t payload_offset,
				  uint8_t *nas_5g, size_t *nas_5g_len,
				  s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/* --- security/ module (Phase 3) --- */
/* Public API declared in security/security.h */
int smc_convert_5g_to_4g(const uint8_t *payload, size_t payload_len,
			 uint8_t *nas_4g, size_t *nas_4g_len,
			 s1n2_security_mode_info_t *info,
			 const uint8_t *mac, bool mac_present,
			 uint8_t seq_no, const ue_id_mapping_t *security_cache);
int smc_complete_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
				  uint8_t first_byte, uint8_t msg_type,
				  size_t payload_offset,
				  uint8_t *nas_5g, size_t *nas_5g_len,
				  s1n2_context_t *ctx, ue_id_mapping_t *ue_map);
int s1n2_compute_5g_uplink_mac(const ue_id_mapping_t *ue_map,
			       const uint8_t *plain_nas, size_t plain_len,
			       uint8_t *mac_out);

/* --- pdu_session/ module (Phase 4) --- */
/* Public API declared in pdu_session/pdu_session.h */
bool s1n2_has_active_pdu_context(const ue_id_mapping_t *map);
uint8_t s1n2_infer_active_pdu_session_id(const ue_id_mapping_t *map);
ue_id_mapping_t *s1n2_find_session_mapping(s1n2_context_t *ctx,
					   ue_id_mapping_t *current);
uint16_t s1n2_build_pdu_session_status_mask(s1n2_context_t *ctx,
					    ue_id_mapping_t *ue_map);
int s1n2_append_pdu_session_status(uint8_t *nas, size_t *offset,
				   size_t capacity, uint16_t status_mask);
int build_pdu_session_establishment_request(uint8_t *nas_5g,
					    size_t *nas_5g_len,
					    ue_id_mapping_t *ue_map,
					    uint8_t pdu_session_id,
					    const char *dnn, uint8_t sst);
int build_gmm_ul_nas_transport_with_n1_sm(uint8_t *nas_5g,
					  size_t *nas_5g_len,
					  ue_id_mapping_t *ue_map,
					  uint8_t pdu_session_id,
					  const char *dnn, uint8_t sst,
					  uint8_t request_type);

/* ================================================================
 * Algorithm mapping tables (from security/security_shared.c)
 * ================================================================ */

// Algorithm mapping tables for 5G↔4G conversion
// These are declared extern if moved to modules, or declared here if shared
extern const uint8_t s1n2_nea_to_eea_map[8];
extern const uint8_t s1n2_nia_to_eia_map[8];

/* ================================================================
 * registration/ module declarations (Phase 5 extraction)
 * ================================================================ */

/* --- 4G→5G converters --- */
int attach_complete_convert_4g_to_5g(uint8_t *nas_5g, size_t *nas_5g_len,
				     ue_id_mapping_t *ue_map);
int attach_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
				    uint8_t first_byte, uint8_t msg_type,
				    size_t payload_offset,
				    uint8_t *nas_5g, size_t *nas_5g_len,
				    s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/* --- 5G→4G converters --- */
int registration_accept_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
					 uint8_t *nas_4g, size_t *nas_4g_len,
					 ue_id_mapping_t *security_cache);
int registration_reject_convert_5g_to_4g(const uint8_t *msg, size_t msg_len,
					 uint8_t *nas_4g, size_t *nas_4g_len);

/* --- Identity helpers --- */
int s1n2_locate_eps_mobile_identity(const uint8_t *nas, size_t nas_len,
				    size_t start_offset,
				    const uint8_t **value_ptr,
				    size_t *value_len);
const char *s1n2_get_fallback_imsi(void);
int s1n2_extract_imsi_from_5g_registration_request(const uint8_t *nas_pdu,
						   size_t nas_len,
						   char *imsi_out,
						   size_t imsi_len);

/* ================================================================
 * tau/ module declarations (Phase 6 extraction)
 * ================================================================ */

/* --- 4G→5G converter --- */
int tau_request_convert_4g_to_5g(const uint8_t *nas_4g, size_t nas_4g_len,
				 uint8_t first_byte, size_t payload_offset,
				 uint8_t *nas_5g, size_t *nas_5g_len,
				 s1n2_context_t *ctx, ue_id_mapping_t *ue_map);

/* --- 5G→4G builder --- */
int s1n2_build_tau_accept_nas(s1n2_context_t *ctx,
			      ue_id_mapping_t *ue_map,
			      uint8_t eps_update_type_octet,
			      uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* S1N2_NAS_MODULE_COMMON_H */
