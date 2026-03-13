/**
 * @file kdf_eps.h
 * @brief 4G EPS Key Derivation Functions API (3GPP TS 33.401)
 */
#ifndef S1N2_KDF_EPS_H
#define S1N2_KDF_EPS_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Derive K_ASME from CK, IK (TS 33.401 Annex A.2)
 */
int s1n2_kdf_kasme(const uint8_t *ck, const uint8_t *ik,
                   const uint8_t *sqn_xor_ak, const uint8_t *plmn_id,
                   uint8_t *kasme);

/**
 * @brief Derive K_NASint or K_NASenc from K_ASME (TS 33.401 Annex A.7)
 */
int s1n2_kdf_nas_keys(const uint8_t *kasme, uint8_t algorithm_type,
                      uint8_t algorithm_id, uint8_t *key_out);

/**
 * @brief Derive both K_NASint and K_NASenc from Ki (convenience)
 *
 * Full key hierarchy: Ki + RAND -> CK, IK -> K_ASME -> K_NASint, K_NASenc
 */
int s1n2_derive_4g_nas_keys(const uint8_t *k, const uint8_t *opc,
                            const uint8_t *rand, const uint8_t *sqn_xor_ak,
                            const uint8_t *plmn_id,
                            uint8_t int_alg, uint8_t enc_alg,
                            uint8_t *k_nas_int, uint8_t *k_nas_enc);

/**
 * @brief Derive KeNB from KASME (TS 33.401 Annex A.3)
 */
int s1n2_kdf_kenb(const uint8_t *kasme, uint32_t ul_count, uint8_t *kenb);

#endif /* S1N2_KDF_EPS_H */
