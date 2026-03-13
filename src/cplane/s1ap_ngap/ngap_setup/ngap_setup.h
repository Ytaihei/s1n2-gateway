/**
 * @file ngap_setup.h
 * @brief NGAP Setup procedure function declarations
 *
 * Builder functions for NGSetupRequest message
 */
#ifndef NGAP_SETUP_H
#define NGAP_SETUP_H

#include <stdint.h>
#include <stddef.h>

/**
 * Build NGAP NGSetupRequest with specified parameters
 *
 * @param buf        Output buffer for encoded message
 * @param len        [in/out] Buffer size / actual encoded length
 * @param mcc        Mobile Country Code (e.g., "310")
 * @param mnc        Mobile Network Code (e.g., "410")
 * @param tac        Tracking Area Code
 * @param gnb_id     gNB ID (22-bit value)
 * @param ran_name   RAN node name
 * @return Encoded message size on success, -1 on failure
 */
int build_ngsetup_request_args(uint8_t *buf, size_t *len,
    const char *mcc, const char *mnc, long tac, uint32_t gnb_id, const char *ran_name);

/**
 * Build NGAP NGSetupRequest from environment variables
 *
 * @param buf        Output buffer for encoded message
 * @param len        [in/out] Buffer size / actual encoded length
 * @return Encoded message size on success, -1 on failure
 *
 * Environment variables used:
 *   - S1N2_MCC / MCC: Mobile Country Code (default "001")
 *   - S1N2_MNC / MNC: Mobile Network Code (default "01")
 *   - S1N2_TAC / TAC: Tracking Area Code (default "1")
 *   - S1N2_RAN_NAME: RAN node name (default "s1n2-gNB")
 */
int build_ngsetup_request_dynamic(uint8_t *buf, size_t *len);

#endif /* NGAP_SETUP_H */
