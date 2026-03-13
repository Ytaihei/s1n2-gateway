#ifndef SUCI_UTILS_H
#define SUCI_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char mcc[4];                // Null-terminated MCC digits (3 chars)
    char mnc[4];                // Null-terminated MNC digits (2 or 3 chars)
    int mnc_len;                // Explicit MNC digit count (2 or 3). If <=0, strlen(mnc) is used.
    char routing_indicator[5];  // Up to 4 digits plus null terminator; empty string means "not provided"
    uint8_t protection_scheme_id;      // 0: Null scheme, 1: Profile A, 2: Profile B
    uint8_t home_network_pki_value;    // HNP KI value (0 for Null scheme)
} suci_builder_config_t;

/**
 * Decode IMSI digits from an EPS Mobile Identity IE value.
 *
 * @param mobile_identity Pointer to the value portion (octets after the length) of the EPS
 *                        Mobile Identity IE.
 * @param mobile_identity_len Length in octets of the value portion.
 * @param imsi_digits Output buffer that receives the decoded digits as a null-terminated string.
 * @param imsi_digits_size Size of @p imsi_digits buffer in bytes.
 * @return Number of digits decoded on success, 0 on failure.
 */
size_t decode_imsi_digits_from_eps_mobile_identity(const uint8_t *mobile_identity,
                                                   size_t mobile_identity_len,
                                                   char *imsi_digits,
                                                   size_t imsi_digits_size);

/**
 * Build a 5GS SUCI Mobile Identity payload from an IMSI digit string.
 *
 * @param imsi_digits Null-terminated string of IMSI digits (no separators).
 * @param imsi_len Number of digits in @p imsi_digits (strlen).
 * @param cfg Builder configuration (PLMN, routing indicator, protection scheme, etc.).
 * @param suci_out Output buffer that receives the SUCI payload (beginning with header octet).
 * @param suci_len In/out parameter: on input, holds size of @p suci_out buffer; on output,
 *                 filled with the number of bytes written.
 * @return 0 on success, negative value on failure.
 */
int suci_build_from_imsi_digits(const char *imsi_digits,
                                size_t imsi_len,
                                const suci_builder_config_t *cfg,
                                uint8_t *suci_out,
                                size_t *suci_len);

/**
 * Convenience helper that decodes an IMSI from an EPS Mobile Identity IE and builds
 * a SUCI payload in one step.
 *
 * @param mobile_identity Pointer to the value portion (octets after length) of the EPS Mobile Identity IE.
 * @param mobile_identity_len Length of the value portion in octets.
 * @param cfg Builder configuration (PLMN, routing indicator, protection scheme, etc.).
 * @param suci_out Output buffer for SUCI payload.
 * @param suci_len In/out parameter with buffer size / bytes written.
 * @param imsi_digits_out Optional buffer to receive decoded IMSI digits (may be NULL).
 * @param imsi_digits_out_len Size of @p imsi_digits_out buffer. Ignored if buffer is NULL.
 * @return 0 on success, negative value on failure.
 */
int suci_build_from_eps_mobile_identity(const uint8_t *mobile_identity,
                                        size_t mobile_identity_len,
                                        const suci_builder_config_t *cfg,
                                        uint8_t *suci_out,
                                        size_t *suci_len,
                                        char *imsi_digits_out,
                                        size_t imsi_digits_out_len);

#ifdef __cplusplus
}
#endif

#endif // SUCI_UTILS_H
