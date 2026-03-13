/**
 * @file kdf_5gs.h
 * @brief 5G Security Key Derivation Functions API (3GPP TS 33.501)
 */
#ifndef S1N2_KDF_5GS_H
#define S1N2_KDF_5GS_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Derive Kausf from CK, IK (TS 33.501 Annex A.2)
 */
int s1n2_kdf_kausf(const uint8_t *ck, const uint8_t *ik,
                   const uint8_t *sqn_xor_ak,
                   const char *serving_network_name,
                   uint8_t *kausf);

/**
 * @brief Derive RES* from Kausf (TS 33.501 Annex A.4) — standard implementation
 */
int s1n2_kdf_res_star_from_kausf(const uint8_t *kausf,
                                  const char *serving_network_name,
                                  const uint8_t *rand,
                                  const uint8_t *res, uint8_t res_len,
                                  uint8_t *res_star);

/**
 * @brief Derive RES* using CK||IK (Open5GS v2.7.2 bug compatibility)
 */
int s1n2_kdf_res_star_from_ck_ik(const uint8_t *ck, const uint8_t *ik,
                                  const char *serving_network_name,
                                  const uint8_t *rand,
                                  const uint8_t *res, uint8_t res_len,
                                  uint8_t *res_star);

/**
 * @brief Derive Kseaf from Kausf (TS 33.501 Annex A.6)
 */
int s1n2_kdf_kseaf(const uint8_t *kausf,
                   const char *serving_network_name,
                   uint8_t *kseaf);

/**
 * @brief Derive Kamf from Kseaf (TS 33.501 Annex A.7)
 */
int s1n2_kdf_kamf(const uint8_t *kseaf,
                  const char *supi,
                  const uint8_t *abba,
                  uint8_t abba_len,
                  uint8_t *kamf);

/**
 * @brief Derive 5G NAS keys from Kamf (TS 33.501 Annex A.8)
 */
int s1n2_kdf_nas_5g(const uint8_t *kamf,
                    uint8_t algorithm_type,
                    uint8_t algorithm_id,
                    uint8_t *key_out);

/**
 * @brief Compute RES* from 4G RES with IMSI (high-level convenience)
 */
struct s1n2_auth_context_s;
int s1n2_auth_compute_res_star_with_imsi(struct s1n2_auth_context_s *auth_ctx,
                                          const char *imsi,
                                          const uint8_t *rand,
                                          const uint8_t *sqn_xor_ak,
                                          const uint8_t *res_4g,
                                          uint8_t res_4g_len,
                                          uint8_t *res_star);

#endif /* S1N2_KDF_5GS_H */
