#include "s1n2_log.h"
/**
 * @file gtp_forward.c
 * @brief G-PDU forwarding with TEID translation
 *
 * Wireshark trace: GTP-U G-PDU (type=255) — TEID rewrite + sendto
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "gtp_header.h"
#include "gtp_tunnel.h"
#include "gtp_uplane_internal.h"

/* ------------------------------------------------------------------ */
/*  Uplink: eNB → s1n2 → UPF  (S1-U → N3 with TEID translation)     */
/* ------------------------------------------------------------------ */
int s1n2_forward_uplink(s1n2_context_t *ctx, uint8_t *data, size_t len,
                        uint32_t teid, ue_id_mapping_t *ue_map) {
    (void)ue_map;
    LOG_INFO("Processing UPLINK: S1-U -> N3 (TEID translation)\n");

    uint8_t *output_packet = NULL;
    size_t output_len = 0;

    if (gtp_tunnel_process_s1u_to_n3(data, len, &output_packet, &output_len) == 0) {
        ssize_t sent = send(ctx->n3_fd, output_packet, output_len, 0);
        free(output_packet);
        if (sent == (ssize_t)output_len) {
            LOG_INFO("UPLINK S1-U→N3 G-PDU forwarded: TEID=0x%08x (%zd bytes)\n",
                   teid, sent);

            return 0;
        }
        LOG_ERROR("Failed to send UPLINK S1-U→N3 G-PDU: %zd\n", sent);

        return -1;
    }

    LOG_ERROR("Uplink TEID conversion failed for TEID=0x%08x\n", teid);

    return -1;
}

/* ------------------------------------------------------------------ */
/*  Downlink: UPF → s1n2 → eNB  (N3 → S1-U, transparent proxy)      */
/* ------------------------------------------------------------------ */
int s1n2_forward_downlink(s1n2_context_t *ctx, uint8_t *data, size_t len,
                          uint32_t teid, ue_id_mapping_t *ue_map) {
    LOG_INFO("Processing DOWNLINK: N3 -> S1-U (Transparent Proxy, no TEID translation)\n");

    uint8_t *output_packet = NULL;
    size_t output_len = 0;

    if (gtp_tunnel_process_n3_to_s1u(data, len, &output_packet, &output_len) != 0) {
        LOG_ERROR("Downlink transparent proxy failed for TEID=0x%08x\n", teid);

        return -1;
    }

    if (!ue_map || !ue_map->has_enb_s1u_info) {
        LOG_ERROR("Downlink packet but no eNB S1-U info for TEID=0x%08x\n", teid);

        free(output_packet);
        return -1;
    }

    struct sockaddr_in enb_addr;
    memset(&enb_addr, 0, sizeof(enb_addr));
    enb_addr.sin_family = AF_INET;
    enb_addr.sin_addr.s_addr = ue_map->enb_s1u_ip;
    enb_addr.sin_port = htons(2152); /* Standard GTP-U port */

    ssize_t sent = sendto(ctx->s1u_fd, output_packet, output_len, 0,
                          (struct sockaddr *)&enb_addr, sizeof(enb_addr));
    free(output_packet);

    if (sent == (ssize_t)output_len) {
        char enb_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ue_map->enb_s1u_ip, enb_ip_str, sizeof(enb_ip_str));
        LOG_INFO("DOWNLINK N3→S1-U G-PDU forwarded: TEID=0x%08x to eNB %s (%zd bytes)\n",
               teid, enb_ip_str, sent);

        return 0;
    }

    LOG_ERROR("Failed to send DOWNLINK N3→S1-U G-PDU: %zd\n", sent);

    return -1;
}
