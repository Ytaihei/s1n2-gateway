#include "s1n2_log.h"
/**
 * @file pdu_session/pdu_session_establishment.c
 * @brief 5G PDU Session Establishment Request builder
 *
 * Extracted from nas_builders.c during Phase 4 NAS modularization.
 *
 * Builds a 5GSM PDU Session Establishment Request with optional
 * integrity protection using K_NASint_5G.
 *
 * @see 3GPP TS 24.501 § 8.3.1 (PDU session establishment request)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "s1n2_nas_internal.h"
#include "s1n2_context_internal.h"
#include "internal/nas_security.h"
#include "internal/nas_conversion_internal.h"
#include "pdu_session/pdu_session.h"

int build_pdu_session_establishment_request(uint8_t *nas_5g,
                                            size_t *nas_5g_len,
                                            ue_id_mapping_t *ue_map,
                                            uint8_t pdu_session_id,
                                            const char *dnn,
                                            uint8_t sst) {
    if (!nas_5g || !nas_5g_len || !dnn) {
        LOG_ERROR("Invalid parameters for PDU Session Establishment Request\n");
        return -1;
    }

    /* Fixed fields, optional DNN and maximum security envelope. */
    if (strlen(dnn) > 99 || *nas_5g_len < 20 + strlen(dnn)) return -1;
    size_t offset = 0;

    // Build plain 5GSM PDU Session Establishment Request
    // Extended protocol discriminator: 5GS session management messages (0x2E)
    nas_5g[offset++] = 0x2E;

    // PDU session identity (8 bits, full byte)
    // TS 24.501 Section 9.4: PDU session ID is 1-15 (0 is reserved)
    nas_5g[offset++] = pdu_session_id;

    // Procedure transaction identity (8 bits, full byte)
    // TS 24.501 Section 9.6: PTI value 1-254 (0 and 255 reserved)
    nas_5g[offset++] = 0x01;  // PTI = 1

    // Message type: PDU session establishment request (0xC1)
    nas_5g[offset++] = 0xC1;

    // Integrity protection maximum data rate (MANDATORY IE, NO IEI!)
    // TS 24.501 Section 8.3.2: Mandatory IEs do not include IEI
    // Format: max rate UL (1 byte) + max rate DL (1 byte)
    nas_5g[offset++] = 0xFF;  // Max data rate UL: 0xFF = 4096 Mbps
    nas_5g[offset++] = 0xFF;  // Max data rate DL: 0xFF = 4096 Mbps

    // PDU session type (optional IE, IEI=0x9-)
    // Format: IEI (4 bits) + PDU session type (4 bits) = 1 byte
    nas_5g[offset++] = 0x91;  // IEI=9, Type=IPv4 (0x01)

    // SSC mode (optional IE, IEI=0xA-)
    // Format: IEI (4 bits) + SSC mode (4 bits) = 1 byte
    nas_5g[offset++] = 0xA1;  // IEI=A, SSC mode 1 (0x01)

    // DNN (Data Network Name) - optional IE, IEI=0x25
    // Format: IEI (1 byte) + Length (1 byte) + DNN (variable)
    size_t dnn_len = strlen(dnn);
    if (dnn_len > 0 && dnn_len < 100) {
        nas_5g[offset++] = 0x25;  // IEI for DNN
        nas_5g[offset++] = (uint8_t)dnn_len;  // Length
        memcpy(&nas_5g[offset], dnn, dnn_len);
        offset += dnn_len;
    }

    // S-NSSAI (Single Network Slice Selection Assistance Information) - optional IE, IEI=0x22
    // Format: IEI (1 byte) + Length (1 byte) + SST (1 byte) + [SD (3 bytes)]
    nas_5g[offset++] = 0x22;  // IEI for S-NSSAI
    nas_5g[offset++] = 0x01;  // Length = 1 (SST only, no SD)
    nas_5g[offset++] = sst;   // SST (Slice Service Type)

    size_t plain_len = offset;

    // If UE context available and has 5G NAS keys, apply integrity protection
    if (ue_map && ue_map->has_5g_nas_keys) {

        LOG_DEBUG("[PDU-SESSION-REQ] COUNT=0x%08X, Direction=0, Bearer=1, Alg=EIA2\n",
               ue_map->nas_ul_count_5g);

        // Compute MAC
        uint8_t mac[4] = {0};
        int ret = s1n2_compute_5g_uplink_mac(
            ue_map,             // UE context with keys and COUNT
            &nas_5g[0],         // Plain NAS message (starts with 0x2E)
            plain_len,
            mac                 // Output MAC
        );

        if (ret != 0) {
            LOG_ERROR("Failed to compute MAC for PDU Session Establishment Request\n");
            return -1;
        }

        // Build security-protected NAS message
        // Move plain NAS to make room for security header
        memmove(&nas_5g[7], &nas_5g[0], plain_len);

        // Security header
        nas_5g[0] = 0x2E;  // Extended protocol discriminator
        nas_5g[1] = 0x01;  // Security header type: Integrity protected (0x01)
        memcpy(&nas_5g[2], mac, 4);  // MAC
        nas_5g[6] = (uint8_t)(ue_map->nas_ul_count_5g & 0xFF);  // Sequence number

        offset = 7 + plain_len;

        // Increment UL COUNT
        ue_map->nas_ul_count_5g++;
        LOG_DEBUG("[PDU-SESSION-REQ] Incremented nas_ul_count_5g to 0x%08X\n",
               ue_map->nas_ul_count_5g);
    }

    *nas_5g_len = offset;

    LOG_INFO("Built PDU Session Establishment Request (PDU Session ID=%u, DNN=%s, SST=%u, len=%zu)\n",
           pdu_session_id, dnn, sst, offset);

    return 0;
}
