/**
 * @file nas_conversion_internal.h
 * @brief Shared helpers for NAS 4G↔5G conversion modules
 *
 * Provides common utility functions, algorithm tables, and constants
 * used across the nas_helpers, nas_4g_to_5g, nas_5g_to_4g, and
 * nas_builders translation units.
 */
#ifndef NAS_CONVERSION_INTERNAL_H
#define NAS_CONVERSION_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "s1n2_converter.h"
#include "suci_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- NAS IE / message type constants ---- */
#define S1N2_5GS_IEI_PDU_SESSION_STATUS 0x50
#define S1N2_5GS_IEI_LAST_VISITED_TAI   0x52
#define S1N2_5GS_IEI_UPDATE_TYPE        0x53
#define S1N2_5GS_IEI_5G_GUTI            0x77

#define S1N2_5GS_REG_TYPE_INITIAL    0x01
#define S1N2_5GS_REG_TYPE_MOBILITY   0x02
#define S1N2_5GS_REG_TYPE_PERIODIC   0x03

#define S1N2_5GS_UPDATE_TYPE_TA_UPDATING        0x04
#define S1N2_5GS_UPDATE_TYPE_PERIODIC_UPDATING  0x06

/* ---- Algorithm mapping tables (NEA↔EEA, NIA↔EIA) ---- */
extern const uint8_t s1n2_nea_to_eea_map[8];
extern const uint8_t s1n2_nia_to_eia_map[8];

/* ---- Logging helpers ---- */
void s1n2_dump_hex(const char *tag, const uint8_t *buf, size_t len);
void s1n2_log_pco_entries(const char *tag, const uint8_t *pco, size_t pco_len);
void s1n2_log_security_mode_result(const char *direction,
				   bool success,
				   uint8_t pd,
				   uint8_t msg_type,
				   const char *details);

/* ---- Crypto helpers ---- */
int s1n2_compute_5g_uplink_mac(const ue_id_mapping_t *ue_map,
			       const uint8_t *plain_nas,
			       size_t plain_len,
			       uint8_t *mac_out);

/* ---- PLMN / TAC / SUCI environment helpers ---- */
void s1n2_copy_digits(const char *src, char *dst, size_t dst_len);
void s1n2_init_suci_config(suci_builder_config_t *cfg);
void s1n2_get_mcc_mnc_from_env(char out_mcc[4], char out_mnc[4], int *out_mnc_len);
void s1n2_encode_plmn_tbcd(const char mcc[4], const char mnc[4],
			   int mnc_len, uint8_t plmn_out[3]);
uint16_t s1n2_get_tac_from_env(void);

/* ---- 5G→4G conversion helpers (nas_5g_to_4g_helpers.c) ---- */
size_t s1n2_safe_strnlen(const char *text, size_t max_len);
size_t s1n2_get_apn_from_env(char *apn_buf, size_t apn_buf_len);
size_t s1n2_encode_apn_label(const char *apn_str, uint8_t *out, size_t out_cap);
void s1n2_cache_registration_accept_artifacts(ue_id_mapping_t *ue_map,
					      const uint8_t *msg,
					      size_t msg_len);
int s1n2_convert_smc_5g_to_4g(const uint8_t *payload,
			      size_t payload_len,
			      uint8_t *nas_4g,
			      size_t *nas_4g_len,
			      s1n2_security_mode_info_t *info,
			      const uint8_t *mac,
			      bool mac_present,
			      uint8_t seq_no,
			      const ue_id_mapping_t *security_cache);

/* ---- 4G→5G conversion helpers (nas_4g_to_5g_helpers.c) ---- */
uint8_t s1n2_map_eps_update_type(uint8_t eps_update_type);
uint8_t s1n2_map_eps_update_type_to_update_ie(uint8_t eps_update_type);
uint8_t s1n2_build_registration_type_octet(uint8_t reg_value,
					   uint8_t follow_on_request,
					   const ue_id_mapping_t *ue_map);
int s1n2_append_update_type(uint8_t *nas, size_t *offset,
			    size_t capacity, uint8_t value);
int s1n2_append_last_visited_tai(uint8_t *nas, size_t *offset,
				 size_t capacity, const ue_id_mapping_t *ue_map);
bool s1n2_has_active_pdu_context(const ue_id_mapping_t *map);
uint8_t s1n2_infer_active_pdu_session_id(const ue_id_mapping_t *map);
ue_id_mapping_t *s1n2_find_session_mapping(s1n2_context_t *ctx,
					   ue_id_mapping_t *current);
uint16_t s1n2_build_pdu_session_status_mask(s1n2_context_t *ctx,
					    ue_id_mapping_t *ue_map);
int s1n2_append_pdu_session_status(uint8_t *nas, size_t *offset,
				   size_t capacity, uint16_t status_mask);
int s1n2_locate_eps_mobile_identity(const uint8_t *nas, size_t nas_len,
				    size_t start_offset,
				    const uint8_t **value_ptr,
				    size_t *value_len);
const char *s1n2_get_fallback_imsi(void);

#ifdef __cplusplus
}
#endif

#endif /* NAS_CONVERSION_INTERNAL_H */
