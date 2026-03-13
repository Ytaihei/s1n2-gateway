/**
 * @file gtp_dispatch.c
 * @brief GTP-U message dispatcher — direction detection + handler routing
 *
 * Implements the public API:  s1n2_handle_gtpu_message()
 *
 * Wireshark trace: all GTP-U packets flow through this dispatcher.
 *   type 1   → gtp_echo.c   (Echo Request)
 *   type 2   → gtp_echo.c   (Echo Response)
 *   type 255 → gtp_forward.c (G-PDU)
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "gtp_header.h"
#include "gtp_tunnel.h"
#include "gtp_uplane_internal.h"

/* ------------------------------------------------------------------
 * Direction detection helpers
 * ------------------------------------------------------------------ */

/**
 * Find matching UE mapping for an uplink TEID.
 * @return pointer to the matching entry, or NULL.
 */
static ue_id_mapping_t *find_uplink_mapping(s1n2_context_t *ctx, uint32_t teid) {
    for (size_t i = 0; i < ctx->num_ue_mappings; i++) {
        if (ctx->ue_mappings[i].in_use &&
            ctx->ue_mappings[i].has_s1n2_uplink_teid &&
            ctx->ue_mappings[i].s1n2_s1u_uplink_teid == teid) {
            return &ctx->ue_mappings[i];
        }
    }
    return NULL;
}

/**
 * Find matching UE mapping for a downlink TEID.
 * @return pointer to the matching entry, or NULL.
 */
static ue_id_mapping_t *find_downlink_mapping(s1n2_context_t *ctx, uint32_t teid) {
    for (size_t i = 0; i < ctx->num_ue_mappings; i++) {
        if (ctx->ue_mappings[i].in_use &&
            ctx->ue_mappings[i].has_enb_s1u_info &&
            ctx->ue_mappings[i].enb_s1u_teid == teid) {
            return &ctx->ue_mappings[i];
        }
    }
    return NULL;
}

static void log_tau_status(const ue_id_mapping_t *ue_map) {
    if (ue_map->in_tau_procedure) {
        printf("[INFO] [TAU-AWARE] UE in TAU procedure, continuing U-Plane forwarding\n");
    }
    if (ue_map->preserve_teid_mapping) {
        printf("[DEBUG] [TAU-AWARE] TEID mapping protected (preserve_teid=true)\n");
    }
    fflush(stdout);
}

/* ------------------------------------------------------------------
 * Public API:  s1n2_handle_gtpu_message()
 * ------------------------------------------------------------------ */

int s1n2_handle_gtpu_message(s1n2_context_t *ctx, uint8_t *data, size_t len) {
    if (len < 8) {
        printf("[DEBUG] GTP-U message too short (%zd bytes)\n", len);
        fflush(stdout);
        return -1;
    }

    uint32_t teid;
    uint8_t message_type;

    if (s1n2_parse_gtpu_header(data, len, &teid, &message_type) != 0) {
        printf("[DEBUG] Invalid GTP-U header\n");
        fflush(stdout);
        return -1;
    }

    printf("[DEBUG] Enhanced GTP-U message: type=%d, TEID=0x%08x, len=%zd\n",
           message_type, teid, len);
    fflush(stdout);

    /* ---- Echo Request / Response ---- */
    if (message_type == 1 || message_type == 2) {
        return s1n2_handle_gtpu_echo(ctx, teid, message_type);
    }

    /* ---- G-PDU (type 0xFF) ---- */
    if (message_type == 0xFF) {
        printf("[DEBUG] Enhanced GTP-U G-PDU processing, TEID=0x%08x\n", teid);
        fflush(stdout);

        /* 1. Check uplink */
        ue_id_mapping_t *ue_up = find_uplink_mapping(ctx, teid);
        if (ue_up) {
            printf("[DEBUG] Detected UPLINK packet: TEID=0x%08x matches s1n2 uplink TEID\n", teid);
            fflush(stdout);
            log_tau_status(ue_up);
            return s1n2_forward_uplink(ctx, data, len, teid, ue_up);
        }

        /* 2. Check downlink */
        ue_id_mapping_t *ue_down = find_downlink_mapping(ctx, teid);
        if (ue_down) {
            printf("[DEBUG] Detected DOWNLINK packet: TEID=0x%08x matches eNB downlink TEID\n", teid);
            fflush(stdout);
            log_tau_status(ue_down);
            return s1n2_forward_downlink(ctx, data, len, teid, ue_down);
        }

        /* 3. Unknown TEID — legacy fallback */
        return s1n2_forward_legacy(ctx, data, len, teid);
    }

    printf("[DEBUG] Unknown GTP-U message type: %d\n", message_type);
    fflush(stdout);
    return 0;
}
