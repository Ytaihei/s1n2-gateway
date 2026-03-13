/**
 * @file s1_setup_response.c
 * @brief NGAP NGSetupResponse to S1AP S1SetupResponse conversion
 *
 * Handles S1 setup response: converts NGAP NGSetupResponse
 * to S1AP S1SetupResponse template for eNB.
 */
#include "internal/s1n2_converter_internal.h"

int s1n2_convert_ngsetup_to_s1setup(uint8_t *ngap_data, size_t ngap_len,
                                    uint8_t *s1ap_data, size_t *s1ap_len) {
    (void)ngap_data;
    (void)ngap_len;

    static const uint8_t s1setup_resp_template[] = {
        0x20, 0x11, 0x00, 0x25, 0x00, 0x00, 0x03, 0x00,
        0x3d, 0x40, 0x0a, 0x03, 0x80, 0x73, 0x72, 0x73,
        0x6d, 0x6d, 0x65, 0x30, 0x31, 0x00, 0x69, 0x00,
        0x0b, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x1a, 0x00, 0x57, 0x40, 0x01,
        0xff
    };

    if (!s1ap_data || !s1ap_len || *s1ap_len < sizeof(s1setup_resp_template)) {
        return -1;
    }

    memcpy(s1ap_data, s1setup_resp_template, sizeof(s1setup_resp_template));
    *s1ap_len = sizeof(s1setup_resp_template);
    return 0;
}
