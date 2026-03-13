/**
 * @file milenage.h
 * @brief Milenage algorithm API (3GPP TS 35.206)
 */
#ifndef S1N2_MILENAGE_H
#define S1N2_MILENAGE_H

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Milenage f2-f5 functions (3GPP TS 35.206)
 *
 * Computes RES, CK, IK, AK from OPc, K, RAND.
 * Any output pointer may be NULL to skip that computation.
 */
void s1n2_milenage_f2345(const uint8_t *opc, const uint8_t *k,
                         const uint8_t *rand,
                         uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);

/**
 * @brief Decode UE's expected SQN from AUTS (3GPP TS 33.102)
 *
 * @param opc OPc (16 bytes)
 * @param k   Ki (16 bytes)
 * @param rand RAND (16 bytes)
 * @param auts AUTS (14 bytes)
 * @param sqn_ms Output: UE's SQN (6 bytes)
 * @return 0 on success, -1 on error
 */
int s1n2_decode_auts_sqn(const uint8_t *opc, const uint8_t *k,
                         const uint8_t *rand, const uint8_t *auts,
                         uint8_t *sqn_ms);

#endif /* S1N2_MILENAGE_H */
