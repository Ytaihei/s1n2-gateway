#include "s1n2_log.h"
/**
 * @file pdu_session/ul_nas_transport.c
 * @brief 5GMM UL NAS Transport with N1 SM information builder
 *
 * Extracted from nas_builders.c during Phase 4 NAS modularization.
 *
 * Wraps a 5GSM PDU Session Establishment Request inside a
 * 5GMM UL NAS Transport message with integrity protection.
 *
 * @see 3GPP TS 24.501 § 8.2.7 (UL NAS Transport)
 * @see 3GPP TS 24.501 § 9.11.3.40 (Payload container type)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "pdu_session/pdu_session.h"

int build_gmm_ul_nas_transport_with_n1_sm(uint8_t *nas_5g,
                                           size_t *nas_5g_len,
                                           ue_id_mapping_t *ue_map,
                                           uint8_t pdu_session_id,
                                           const char *dnn,
                                           uint8_t sst,
                                           uint8_t request_type) {
    if (!nas_5g || !nas_5g_len || !ue_map || !dnn) {
        LOG_ERROR("Invalid parameters for UL NAS Transport with N1 SM\n");
        return -1;
    }

    // Step 1: Build inner 5GSM PDU Session Establishment Request (plain, no security header)
    // TS 24.501 Section 8.3: 5GSM message structure (ALL MANDATORY):
    // 1. Extended protocol discriminator (EPD) - 0x2E
    // 2. PDU session identity - 1 octet
    // 3. Procedure transaction identity (PTI) - 1 octet
    // 4. Message type - 1 octet
    // 5. Other IEs
    uint8_t gsm_payload[512];
    size_t gsm_len = sizeof(gsm_payload);
    size_t offset_gsm = 0;

    // Extended protocol discriminator (EPD) for 5GSM - MANDATORY
    // TS 24.501 Section 9.2: EPD = 0x2E for 5G session management messages
    gsm_payload[offset_gsm++] = 0x2E;

    // PDU session identity - MANDATORY
    // TS 24.501 Section 9.4: PDU session ID value 1-15
    gsm_payload[offset_gsm++] = pdu_session_id;

    // Procedure transaction identity (PTI) - MANDATORY
    // TS 24.501 Section 9.6: PTI value 1-254 (0 and 255 reserved)
    gsm_payload[offset_gsm++] = 0x01;  // PTI = 1

    // Message type: PDU session establishment request (0xC1)
    gsm_payload[offset_gsm++] = 0xC1;

    // Integrity protection maximum data rate (MANDATORY IE, NO IEI!)
    // TS 24.501 Section 8.3.2: Mandatory IEs do not include IEI
    // Format: max rate UL (1 byte) + max rate DL (1 byte)
    gsm_payload[offset_gsm++] = 0xFF;  // Max data rate UL: 0xFF = 4096 Mbps
    gsm_payload[offset_gsm++] = 0xFF;  // Max data rate DL: 0xFF = 4096 Mbps

    // PDU session type (optional IE, IEI=0x9-)
    gsm_payload[offset_gsm++] = 0x91;  // IEI=9, Type=IPv4 (0x01)

    // SSC mode (optional IE, IEI=0xA-)
    gsm_payload[offset_gsm++] = 0xA1;  // IEI=A, SSC mode 1 (0x01)

    // NOTE: DNN and S-NSSAI are NOT included in 5GSM Payload container!
    // Per TS 29.502 Section 5.2.2, DNN and S-NSSAI are provided as JSON parameters
    // in SmContextCreateData, not in the n1SmMsg (5GSM Payload container).
    // The AMF will extract DNN and S-NSSAI from the UL NAS Transport IEs (or subscription)
    // and include them in the HTTP POST JSON body when forwarding to SMF.
    //
    // Including DNN (IEI=0x25) and S-NSSAI (IEI=0x22) in the 5GSM Payload container
    // causes Open5GS SMF decoder to fail with "Unknown type(0x25)" errors because
    // the decoder does not expect these IEs in the SBI context.

    gsm_len = offset_gsm;

    LOG_DEBUG("[UL-NAS-TRANSPORT] Built inner 5GSM payload (%zu bytes)\n", gsm_len);

    // Step 2: Build 5GMM UL NAS Transport (plain, before security)
    uint8_t gmm_plain[1024];
    size_t offset_gmm = 0;

    // Extended protocol discriminator: 5GS mobility management messages (0x7E)
    gmm_plain[offset_gmm++] = 0x7E;

    // Security header type: Plain NAS message (0x00) - will be replaced with security header later
    gmm_plain[offset_gmm++] = 0x00;

		// Message type: UL NAS Transport (0x67 = 103 decimal per TS 24.501)
		gmm_plain[offset_gmm++] = 0x67;

    // Payload container type (mandatory IE, half octet IEI=0xF-)
    // TS 24.501 Section 9.11.3.40: N1 SM information = 0x01
    gmm_plain[offset_gmm++] = 0xF1;  // IEI=F, Type=N1 SM information (0x01)

    // Payload container (mandatory IE)
    // Format: Length (2 bytes, big-endian) + Payload
    uint16_t payload_len = (uint16_t)gsm_len;
    gmm_plain[offset_gmm++] = (payload_len >> 8) & 0xFF;  // Length high byte
    gmm_plain[offset_gmm++] = payload_len & 0xFF;         // Length low byte
    memcpy(&gmm_plain[offset_gmm], gsm_payload, gsm_len);
    offset_gmm += gsm_len;

    // PDU session ID (optional IE, Type 4: IEI=0x12)
    // TS 24.501 Section 8.2.7: UL NAS Transport - PDU session ID IE has IEI=0x12
    // TS 24.501 Section 9.11.3.41: PDU session identity 2 (Type TV, 1 octet)
    // Format: IEI (1 byte 0x12) is NOT included in Type TV - just the value (4 bits used)
    // Actually this is Type 1 IE with upper nibble as IEI
    gmm_plain[offset_gmm++] = 0x12;  // IEI for PDU session ID in UL NAS Transport
    gmm_plain[offset_gmm++] = pdu_session_id;  // PDU session ID value

    // Request type (optional IE, IEI=0x8-)
    // Format: IEI (4 bits) + Request type (4 bits) = 1 byte
    gmm_plain[offset_gmm++] = 0x80 | (request_type & 0x0F);  // IEI=8, Request type

    // S-NSSAI (optional IE, IEI=0x22) - include in outer UL NAS Transport as well
    gmm_plain[offset_gmm++] = 0x22;  // IEI
    gmm_plain[offset_gmm++] = 0x01;  // Length = 1
    gmm_plain[offset_gmm++] = sst;

    // NOTE: DNN IE is NOT included in UL NAS Transport message per TS 24.501 Section 8.2.7
    // DNN is only included in the inner 5GSM payload (PDU Session Establishment Request)

    size_t gmm_plain_len = offset_gmm;

    LOG_DEBUG("[UL-NAS-TRANSPORT] Built plain 5GMM UL NAS Transport (%zu bytes)\n", gmm_plain_len);

    // Step 3: Apply security (integrity protection)
    if (!ue_map->has_5g_nas_keys) {
        LOG_ERROR("[UL-NAS-TRANSPORT] No 5G NAS keys available for integrity protection\n");
        return -1;
    }

    LOG_DEBUG("[UL-NAS-TRANSPORT] Computing 5G uplink MAC\n");
    LOG_DEBUG("[UL-NAS-TRANSPORT] COUNT=0x%08X, Direction=0, Bearer=1, Alg=EIA2\n",
           ue_map->nas_ul_count_5g);

    // Compute MAC over inner plain GMM (from EPD=0x7E), s1n2_compute_5g_uplink_mac will prepend SEQ
    uint8_t mac[4] = {0};
    int ret = s1n2_compute_5g_uplink_mac(ue_map, gmm_plain, gmm_plain_len, mac);
    if (ret != 0) {
        LOG_ERROR("[UL-NAS-TRANSPORT] Failed to compute MAC\n");
        return -1;
    }

    // Sequence number (lower 8 bits of UL COUNT)
    uint8_t seq = (uint8_t)(ue_map->nas_ul_count_5g & 0xFF);

    // Step 4: Build final security-protected message
    size_t offset_final = 0;

    // Extended protocol discriminator
    nas_5g[offset_final++] = 0x7E;

    // Security header type: Integrity protected (0x01)
    nas_5g[offset_final++] = 0x01;

    // Message authentication code (MAC)
    memcpy(&nas_5g[offset_final], mac, 4);
    offset_final += 4;

	// Sequence number (lower 8 bits of UL COUNT)
	nas_5g[offset_final++] = seq;

	// Plain NAS message should include inner EPD(0x7E) and inner SecHdr(0x00)
	// Copy entire GMM plain (EPD + SecHdr + Message Type + IEs)
	memcpy(&nas_5g[offset_final], gmm_plain, gmm_plain_len);
	offset_final += gmm_plain_len;

    *nas_5g_len = offset_final;

    // Increment UL COUNT
    ue_map->nas_ul_count_5g++;
    LOG_DEBUG("[UL-NAS-TRANSPORT] Incremented nas_ul_count_5g to 0x%08X\n",
           ue_map->nas_ul_count_5g);

    LOG_INFO("Built 5GMM UL NAS Transport with N1 SM (PSI=%u, DNN=%s, SST=%u, ReqType=%u, len=%zu)\n",
           pdu_session_id, dnn, sst, request_type, offset_final);

    return 0;
}
