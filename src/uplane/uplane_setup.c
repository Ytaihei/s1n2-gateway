/*
 * s1n2_uplane.c – U-Plane setup helpers
 *
 * Contains the TEID/endpoint logic that was previously inlined inside
 * C-Plane converter functions.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "uplane_setup.h"
#include "s1n2_converter.h"          /* ue_id_mapping_t, s1n2_context_t, e_rab_setup_info_t */
#include "gtp_tunnel.h"              /* gtp_tunnel_add_mapping{,_explicit} */

/* ================================================================== */
/*  s1n2_uplane_select_s1u_endpoint                                   */
/* ================================================================== */
int s1n2_uplane_select_s1u_endpoint(const s1n2_context_t *ctx,
                                    ue_id_mapping_t       *ue_map,
                                    uint32_t *s1u_ip_be,
                                    uint32_t *s1u_teid_be,
                                    uint8_t  *e_rab_id)
{
    if (!s1u_ip_be || !s1u_teid_be || !e_rab_id) return -1;

    *s1u_ip_be   = 0;
    *s1u_teid_be = 0;
    *e_rab_id    = 5;

    /* 1) Cached E-RAB context (from earlier AMF signaling) */
    if (ctx && ctx->num_e_rab_contexts > 0) {
        const e_rab_setup_info_t *last =
            &ctx->e_rab_contexts[ctx->num_e_rab_contexts - 1];

        if (last->ul_transport_address)
            *s1u_ip_be = last->ul_transport_address;
        else
            *s1u_ip_be = ctx->s1u_addr.sin_addr.s_addr;

        if (last->ul_gtp_teid)
            *s1u_teid_be = htonl(last->ul_gtp_teid);
        if (last->e_rab_id)
            *e_rab_id = last->e_rab_id;

        printf("[DEBUG] [ICS] Using cached E-RAB ctx: EBI=%u, TEID=0x%08X, S1U=%s\n",
               *e_rab_id, ntohl(*s1u_teid_be),
               inet_ntoa(*(struct in_addr *)s1u_ip_be));
        return 0;
    }

    /* 2) No cached E-RAB – determine address from env/bind */
    const char *s1u_advertise = getenv("S1U_ADVERTISE_ADDR");
    if (s1u_advertise && s1u_advertise[0] &&
        strcmp(s1u_advertise, "0.0.0.0") != 0) {
        *s1u_ip_be = inet_addr(s1u_advertise);
        printf("[INFO] [ICS] Using S1U_ADVERTISE_ADDR (bridge mode): %s\n",
               s1u_advertise);
    } else if (ctx &&
               ctx->s1u_addr.sin_addr.s_addr != 0 &&
               ctx->s1u_addr.sin_addr.s_addr != htonl(INADDR_ANY)) {
        *s1u_ip_be = ctx->s1u_addr.sin_addr.s_addr;
        printf("[INFO] [ICS] Using s1n2 S1-U bind address (bridge mode): %s\n",
               inet_ntoa(ctx->s1u_addr.sin_addr));
    } else {
        const char *upf_s1u = getenv("UPF_S1U_ADDR");
        if (upf_s1u && upf_s1u[0]) {
            *s1u_ip_be = inet_addr(upf_s1u);
            printf("[WARN] [ICS] Falling back to UPF_S1U_ADDR from env (direct mode): %s\n",
                   upf_s1u);
        } else {
            *s1u_ip_be = inet_addr("172.24.0.21");
            printf("[WARN] [ICS] Using default UPF IP (direct mode): 172.24.0.21\n");
        }
    }

    *s1u_teid_be = htonl(0x00000001);
    *e_rab_id    = 5;
    printf("[INFO] [ICS] Fallback E-RAB setup: EBI=%u, TEID=0x%08X, S1U=%s\n",
           *e_rab_id, ntohl(*s1u_teid_be),
           inet_ntoa(*(struct in_addr *)s1u_ip_be));

    /* Store s1n2's own S1-U uplink TEID for later deferred mapping */
    if (ue_map) {
        ue_map->s1n2_s1u_uplink_teid = ntohl(*s1u_teid_be);
        ue_map->has_s1n2_uplink_teid = true;
        printf("[INFO] [ICS] Stored s1n2 S1-U uplink TEID 0x%08x for deferred uplink mapping\n",
               ue_map->s1n2_s1u_uplink_teid);
    }
    return 0;
}

/* ================================================================== */
/*  s1n2_uplane_register_ics_erab                                     */
/* ================================================================== */
int s1n2_uplane_register_ics_erab(const s1n2_context_t *ctx,
                                  ue_id_mapping_t      *ue_map,
                                  uint32_t              s1u_teid,
                                  uint32_t              s1u_ip_be,
                                  uint16_t              e_rab_id,
                                  uint8_t               pdu_session_id)
{
    if (s1u_teid == 0) return 0;   /* nothing to do */

    uint16_t s1u_port_be = htons(2152);

    /* Store eNB S1-U tunnel info in UE mapping */
    if (ue_map) {
        ue_map->enb_s1u_ip       = s1u_ip_be;
        ue_map->enb_s1u_teid     = s1u_teid;
        ue_map->has_enb_s1u_info = true;
    }

    /* Proxy mode: UPF N3 info already available? */
    if (ue_map && ue_map->has_upf_n3_info && ue_map->upf_n3_teid > 0) {
        char enb_ip_str[INET_ADDRSTRLEN], upf_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &s1u_ip_be,           enb_ip_str, sizeof(enb_ip_str));
        inet_ntop(AF_INET, &ue_map->upf_n3_ip,   upf_ip_str, sizeof(upf_ip_str));

        printf("[INFO] [ICS] PROXY MODE: Will map S1-U TEID 0x%08x → N3 TEID 0x%08x (UPF's downlink TEID)\n",
               s1u_teid, ue_map->upf_n3_teid);

        int ret = gtp_tunnel_add_mapping_explicit(
            s1u_teid,
            s1u_ip_be,
            s1u_port_be,
            ue_map->upf_n3_ip,
            htons(2152),
            ue_map->upf_n3_teid,
            pdu_session_id,
            e_rab_id,
            ue_map->qfi);

        if (ret > 0) {
            printf("[INFO] [ICS] Registered explicit TEID mapping S1-U 0x%08x ↔ N3 0x%08x (ENB %s ↔ UPF %s, PDU %u, E-RAB %u)\n",
                   s1u_teid, ue_map->upf_n3_teid, enb_ip_str, upf_ip_str,
                   pdu_session_id, e_rab_id);
        } else {
            printf("[WARN] [ICS] Failed to register explicit TEID mapping S1-U 0x%08x ↔ N3 0x%08x\n",
                   s1u_teid, ue_map->upf_n3_teid);
        }
        return ret;
    }

    /* Fallback: 1:1 mapping when UPF info is not yet available */
    if (!ctx) return -1;
    int new_n3 = gtp_tunnel_add_mapping(
        s1u_teid,
        s1u_ip_be,
        s1u_port_be,
        ctx->n3_addr.sin_addr.s_addr,
        ctx->n3_addr.sin_port,
        pdu_session_id,
        e_rab_id,
        ue_map ? ue_map->qfi : 1);

    if (new_n3 > 0) {
        printf("[INFO] [ICS] Pre-registered TEID mapping (1:1) S1-U 0x%08x ↔ N3 0x%08x\n",
               s1u_teid, (uint32_t)new_n3);
    } else {
        printf("[WARN] [ICS] Failed to pre-register TEID mapping for S1-U TEID=0x%08x\n",
               s1u_teid);
    }
    return new_n3;
}

/* ================================================================== */
/*  s1n2_uplane_register_dl_mapping                                   */
/* ================================================================== */
int s1n2_uplane_register_dl_mapping(uint32_t enb_teid,
                                    uint32_t enb_ip_be,
                                    uint32_t upf_n3_teid,
                                    uint32_t upf_n3_ip_be,
                                    uint8_t  pdu_session_id,
                                    uint16_t e_rab_id)
{
    char enb_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &enb_ip_be, enb_ip_str, sizeof(enb_ip_str));

    printf("[INFO] [TEID-MAP] Registering downlink mapping: N3 TEID 0x%08x -> S1-U TEID 0x%08x (eNB %s)\n",
           upf_n3_teid, enb_teid, enb_ip_str);

    int result = gtp_tunnel_add_mapping_explicit(
        enb_teid,
        enb_ip_be,
        htons(2152),
        upf_n3_ip_be,
        htons(2152),
        upf_n3_teid,
        pdu_session_id,
        e_rab_id,
        0);

    if (result >= 0) {
        printf("[INFO] [TEID-MAP] Successfully registered bidirectional TEID mapping\n");
    } else {
        printf("[ERROR] [TEID-MAP] Failed to register TEID mapping\n");
    }
    return result;
}

/* ================================================================== */
/*  s1n2_uplane_store_upf_n3_and_map                                  */
/* ================================================================== */
void s1n2_uplane_store_upf_n3_and_map(s1n2_context_t  *ctx,
                                      ue_id_mapping_t *ue_map,
                                      uint32_t         upf_ip_be,
                                      uint32_t         upf_teid,
                                      uint8_t          pdu_session_id,
                                      uint8_t          e_rab_id)
{
    if (!ue_map) {
        printf("[WARN]     No active UE mapping found to store UPF N3 info\n");
        return;
    }

    /* Store UPF N3 info */
    ue_map->upf_n3_ip   = upf_ip_be;
    ue_map->upf_n3_teid = upf_teid;
    ue_map->has_upf_n3_info = true;
    printf("[INFO]     Stored UPF N3 info in UE context (ENB=%ld, UPF N3 TEID=0x%08x)\n",
           ue_map->enb_ue_s1ap_id, ue_map->upf_n3_teid);

    /* ---- Deferred UPLINK mapping ---- */
    if (ue_map->has_s1n2_uplink_teid && ue_map->s1n2_s1u_uplink_teid > 0) {
        printf("[INFO]     Creating deferred uplink TEID mapping (s1n2 uplink TEID -> UPF N3 TEID)\n");
        if (ctx) {
            printf("[DEBUG]    s1n2 S1-U uplink: IP=%s, TEID=0x%08x\n",
                   inet_ntoa(ctx->s1u_addr.sin_addr),
                   ue_map->s1n2_s1u_uplink_teid);
        }
        printf("[DEBUG]    UPF N3: IP=%s, TEID=0x%08x\n",
               inet_ntoa(*(struct in_addr *)&ue_map->upf_n3_ip),
               ue_map->upf_n3_teid);

        uint32_t s1n2_ip = ctx ? ctx->s1u_addr.sin_addr.s_addr : 0;
        int uplink_result = gtp_tunnel_add_mapping_explicit(
            ue_map->s1n2_s1u_uplink_teid,
            s1n2_ip,
            htons(2152),
            ue_map->upf_n3_ip,
            htons(2152),
            ue_map->upf_n3_teid,
            pdu_session_id,
            e_rab_id,
            ue_map->qfi);

        if (uplink_result > 0) {
            char upf_ip_str[INET_ADDRSTRLEN], s1n2_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ue_map->upf_n3_ip, upf_ip_str, INET_ADDRSTRLEN);
            if (ctx) inet_ntop(AF_INET, &ctx->s1u_addr.sin_addr, s1n2_ip_str, INET_ADDRSTRLEN);
            else     strcpy(s1n2_ip_str, "?");
            printf("[INFO]     ✓ Uplink TEID mapping created: S1-U 0x%08x (s1n2 %s) → N3 0x%08x (UPF %s)\n",
                   ue_map->s1n2_s1u_uplink_teid, s1n2_ip_str,
                   ue_map->upf_n3_teid, upf_ip_str);
        } else {
            printf("[WARN]     Failed to create uplink TEID mapping (may already exist)\n");
        }
    } else {
        printf("[INFO]     s1n2 uplink TEID not yet allocated; uplink mapping will be created later\n");
    }

    /* ---- Deferred DOWNLINK mapping ---- */
    if (ue_map->ics_completed && ue_map->has_enb_s1u_info && ue_map->enb_s1u_teid > 0) {
        printf("[INFO]     Ensuring explicit downlink TEID mapping after receiving UPF N3 info\n");
        printf("[DEBUG]    eNB S1-U: IP=%s, TEID=0x%08x\n",
               inet_ntoa(*(struct in_addr *)&ue_map->enb_s1u_ip),
               ue_map->enb_s1u_teid);
        printf("[DEBUG]    UPF N3: IP=%s, TEID=0x%08x\n",
               inet_ntoa(*(struct in_addr *)&ue_map->upf_n3_ip),
               ue_map->upf_n3_teid);

        int result = gtp_tunnel_add_mapping_explicit(
            ue_map->enb_s1u_teid,
            ue_map->enb_s1u_ip,
            htons(2152),
            ue_map->upf_n3_ip,
            htons(2152),
            ue_map->upf_n3_teid,
            pdu_session_id,
            e_rab_id,
            ue_map->qfi);

        if (result > 0) {
            char upf_ip_str[INET_ADDRSTRLEN], enb_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &ue_map->upf_n3_ip, upf_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ue_map->enb_s1u_ip, enb_ip_str, INET_ADDRSTRLEN);
            printf("[INFO]     ✓ Downlink TEID mapping created: N3 0x%08x (UPF %s) → S1-U 0x%08x (eNB %s)\n",
                   ue_map->upf_n3_teid, upf_ip_str,
                   ue_map->enb_s1u_teid, enb_ip_str);
        } else {
            printf("[WARN]     Failed to ensure explicit downlink TEID mapping (may already exist)\n");
        }
    } else {
        printf("[INFO]     Waiting for S1AP ICS Response to complete downlink TEID mapping\n");
        printf("[DEBUG]    ics_completed=%d, has_enb_s1u_info=%d, enb_s1u_teid=0x%08x\n",
               ue_map->ics_completed, ue_map->has_enb_s1u_info, ue_map->enb_s1u_teid);
    }
}
