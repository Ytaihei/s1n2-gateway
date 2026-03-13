/**
 * @file nas_transport.h
 * @brief NAS Transport conversion function declarations
 *
 * Downlink (S1AP → NGAP) and Uplink (S1AP → NGAP) NAS transport conversion,
 * plus NGAP → S1AP downlink reverse conversion.
 */
#ifndef NAS_TRANSPORT_H
#define NAS_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>

/* Forward declarations to avoid full header inclusion */
typedef struct s1n2_context s1n2_context_t;
typedef struct ue_id_mapping ue_id_mapping_t;

/**
 * @brief Convert S1AP DownlinkNASTransport to NGAP DownlinkNASTransport.
 *
 * Decodes S1AP message, performs 4G→5G NAS conversion, and builds
 * NGAP DownlinkNASTransport.
 *
 * @param ctx       Converter context
 * @param s1ap_data S1AP encoded message
 * @param s1ap_len  Length of S1AP message
 * @param ngap_data Output buffer for NGAP message
 * @param ngap_len  [in/out] Buffer size / encoded length
 * @return 0 on success, -1 on failure
 */
int s1n2_convert_downlink_nas_transport(s1n2_context_t *ctx,
                                        uint8_t *s1ap_data, size_t s1ap_len,
                                        uint8_t *ngap_data, size_t *ngap_len);

/**
 * @brief Convert NGAP DownlinkNASTransport to S1AP DownlinkNASTransport.
 *
 * Decodes NGAP message, performs 5G→4G NAS conversion, and builds
 * S1AP DownlinkNASTransport (or S1AP InitialContextSetupRequest for
 * Attach Accept bridging).
 *
 * @param ctx       Converter context
 * @param ngap_data NGAP encoded message
 * @param ngap_len  Length of NGAP message
 * @param s1ap_data Output buffer for S1AP message
 * @param s1ap_len  [in/out] Buffer size / encoded length
 * @return 0 on success, -1 on failure
 */
int s1n2_convert_ngap_downlink_nas_transport(s1n2_context_t *ctx,
                                             uint8_t *ngap_data, size_t ngap_len,
                                             uint8_t *s1ap_data, size_t *s1ap_len);

/**
 * @brief Convert S1AP UplinkNASTransport to NGAP UplinkNASTransport.
 *
 * Decodes S1AP message, performs NAS security processing (MAC verify,
 * decryption), 4G→5G NAS conversion, and builds NGAP UplinkNASTransport.
 * Also handles TAU termination and Auth Failure fallback.
 *
 * @param ctx       Converter context
 * @param s1ap_data S1AP encoded message
 * @param s1ap_len  Length of S1AP message
 * @param ngap_data Output buffer for NGAP message
 * @param ngap_len  [in/out] Buffer size / encoded length
 * @return 0 on success, -1 on failure
 */
int s1n2_convert_uplink_nas_transport(s1n2_context_t *ctx,
                                      uint8_t *s1ap_data, size_t s1ap_len,
                                      uint8_t *ngap_data, size_t *ngap_len);

#endif /* NAS_TRANSPORT_H */
