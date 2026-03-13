#ifndef S1N2_SECURITY_H
#define S1N2_SECURITY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @file s1n2_security.h
 * @brief NAS security functions for 4G/5G interworking
 *
 * Implements NAS integrity protection (MAC calculation) and encryption
 * for LTE (EPS) NAS messages, as specified in 3GPP TS 33.401.
 */

/**
 * NAS integrity algorithms (EIA - EPS Integrity Algorithm)
 */
typedef enum {
    S1N2_NAS_EIA0 = 0,  /**< NULL integrity (no protection) */
    S1N2_NAS_EIA1 = 1,  /**< SNOW 3G based */
    S1N2_NAS_EIA2 = 2,  /**< AES-CMAC based (most common) */
    S1N2_NAS_EIA3 = 3,  /**< ZUC based */
} s1n2_nas_integrity_alg_t;

/**
 * NAS encryption algorithms (EEA - EPS Encryption Algorithm)
 */
typedef enum {
    S1N2_NAS_EEA0 = 0,  /**< NULL encryption (no protection) */
    S1N2_NAS_EEA1 = 1,  /**< SNOW 3G based */
    S1N2_NAS_EEA2 = 2,  /**< AES-CTR based */
    S1N2_NAS_EEA3 = 3,  /**< ZUC based */
} s1n2_nas_encryption_alg_t;

/**
 * @brief Compute NAS MAC-I (Message Authentication Code for Integrity)
 *
 * Calculates 32-bit MAC for NAS message integrity protection using the
 * specified algorithm and key. The MAC is computed over the entire NAS
 * message including security header (if present).
 *
 * @param algorithm    Integrity algorithm (EIA1/EIA2/EIA3)
 * @param key          128-bit NAS integrity key (K_NASint)
 * @param count        32-bit NAS COUNT value (NAS sequence number)
 * @param bearer       5-bit bearer identity (usually 0 for NAS)
 * @param direction    1-bit direction (0=uplink, 1=downlink)
 * @param message      Input NAS message buffer
 * @param msg_len      Length of input message in bytes
 * @param mac_out      Output buffer for 32-bit MAC (4 bytes)
 * @return 0 on success, negative on error
 *
 * @note Implements algorithms from 3GPP TS 33.401 Annex B
 */
int s1n2_nas_compute_mac(
    s1n2_nas_integrity_alg_t algorithm,
    const uint8_t *key,         // 16 bytes
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t *message,
    size_t msg_len,
    uint8_t *mac_out            // 4 bytes
);

/**
 * @brief Encrypt/decrypt NAS message payload
 *
 * @param algorithm    Encryption algorithm (EEA1/EEA2/EEA3)
 * @param key          128-bit NAS encryption key (K_NASenc)
 * @param count        32-bit NAS COUNT value
 * @param bearer       5-bit bearer identity
 * @param direction    1-bit direction (0=uplink, 1=downlink)
 * @param input        Input data buffer
 * @param input_len    Length of input in bytes
 * @param output       Output buffer (must be at least input_len bytes)
 * @return 0 on success, negative on error
 *
 * @note For stream ciphers, encryption and decryption are the same operation
 */
int s1n2_nas_encrypt(
    s1n2_nas_encryption_alg_t algorithm,
    const uint8_t *key,
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output
);

/**
 * @brief Helper: Compute NAS MAC for 4G Security Mode Command
 *
 * Convenience function for computing MAC specifically for Security Mode Command
 * messages in downlink direction.
 *
 * @param algorithm    Integrity algorithm
 * @param key          K_NASint (16 bytes)
 * @param count        NAS COUNT (typically sequence number)
 * @param plain_nas    Plain NAS message (without security header)
 * @param plain_len    Length of plain NAS message
 * @param mac_out      Output MAC (4 bytes)
 * @return 0 on success, negative on error
 */
int s1n2_compute_smc_mac(
    s1n2_nas_integrity_alg_t algorithm,
    const uint8_t *key,
    uint32_t count,
    const uint8_t *plain_nas,
    size_t plain_len,
    uint8_t *mac_out
);

/**
 * @brief Test NAS MAC calculation with known test vectors
 *
 * Validates the MAC implementation against test vectors from 3GPP specs.
 *
 * @return 0 if all tests pass, negative otherwise
 */
int s1n2_test_nas_mac(void);

#endif /* S1N2_SECURITY_H */
