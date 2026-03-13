/**
 * @file s1_setup.h
 * @brief S1AP Setup procedure function declarations
 *
 * Conversion functions for S1SetupRequest/Response messages
 */
#ifndef S1_SETUP_H
#define S1_SETUP_H

#include <stdint.h>
#include <stddef.h>

/**
 * Convert S1AP S1SetupRequest to NGAP NGSetupRequest
 *
 * @param s1ap_data  Input S1AP message
 * @param s1ap_len   Input length
 * @param ngap_data  Output NGAP message buffer
 * @param ngap_len   [in/out] Output buffer size / actual encoded length
 * @return 0 on success, -1 on failure
 */
int s1n2_convert_s1setup_to_ngsetup(uint8_t *s1ap_data, size_t s1ap_len,
                                    uint8_t *ngap_data, size_t *ngap_len);

/**
 * Convert NGAP NGSetupResponse to S1AP S1SetupResponse (template)
 *
 * @param ngap_data  Input NGAP message (unused for template mode)
 * @param ngap_len   Input length (unused for template mode)
 * @param s1ap_data  Output S1AP message buffer
 * @param s1ap_len   [in/out] Output buffer size / actual message length
 * @return 0 on success, -1 on failure
 */
int s1n2_convert_ngsetup_to_s1setup(uint8_t *ngap_data, size_t ngap_len,
                                    uint8_t *s1ap_data, size_t *s1ap_len);

#endif /* S1_SETUP_H */
