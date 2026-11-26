#include "s1n2_log.h"
#include "s1n2_converter.h"
#include "internal/s1n2_context_internal.h"
#include "ics.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

/**
 * Enqueue pending S1AP InitialContextSetupResponse for deferred NGAP conversion
 */
int ics_state_enqueue_pending_s1ap_ics(s1n2_context_t *ctx,
                                       const uint8_t *s1ap_data,
                                       size_t s1ap_len) {
    if (!ctx || !s1ap_data || s1ap_len == 0) {
        LOG_ERROR("ics_state_enqueue: Invalid parameters\n");
        return -1;
    }

    // Find most recent UE mapping (by security context establishment timing)
    ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
    if (!ue_map) {
        LOG_WARN("ics_state_enqueue: No UE mapping found for pending ICS\n");
        return -1;
    }

    // Cache S1AP ICS Response data
    size_t copy_len = (s1ap_len <= sizeof(ue_map->pending_s1ap_ics)) ?
                      s1ap_len : sizeof(ue_map->pending_s1ap_ics);

    memcpy(ue_map->pending_s1ap_ics, s1ap_data, copy_len);
    ue_map->pending_s1ap_ics_len = copy_len;
    ue_map->has_pending_s1ap_ics = true;

    LOG_INFO("[ICS] Cached S1AP InitialContextSetupResponse (%zu bytes) for UE (AMF-UE-ID=%ld)\n",
           copy_len, ue_map->amf_ue_ngap_id);

    return 0;
}

/**
 * Dequeue and convert pending S1AP ICS Response to NGAP
 */
int ics_state_dequeue_pending_s1ap_ics(s1n2_context_t *ctx,
                                       uint8_t *ngap_data,
                                       size_t *ngap_len) {
    if (!ctx || !ngap_data || !ngap_len) {
        LOG_ERROR("ics_state_dequeue: Invalid parameters\n");
        return -1;
    }

    // Find UE mapping with pending ICS
    ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
    if (!ue_map || !ue_map->has_pending_s1ap_ics || ue_map->pending_s1ap_ics_len == 0) {
        return -1; // No pending ICS available
    }

    // Convert S1AP ICS Response to NGAP
    extern int s1n2_convert_initial_context_setup_response(
        uint8_t *s1ap_data, size_t s1ap_len,
        uint8_t *ngap_data, size_t *ngap_len,
        s1n2_context_t *ctx);

    int ret = s1n2_convert_initial_context_setup_response(
        ue_map->pending_s1ap_ics,
        ue_map->pending_s1ap_ics_len,
        ngap_data,
        ngap_len,
        ctx
    );

    if (ret == 0) {
        LOG_INFO("[ICS] Converted cached S1AP ICS Response to NGAP (%zu bytes, QFI=%u)\n",
               *ngap_len, ue_map->qfi);

        // Clear cached data
        ue_map->has_pending_s1ap_ics = false;
        ue_map->pending_s1ap_ics_len = 0;
    } else {
        LOG_ERROR("[ICS] Failed to convert cached S1AP ICS Response to NGAP\n");
    }

    return ret;
}

/**
 * Mark that AMF has sent InitialContextSetupRequest
 */
int ics_state_mark_amf_ics_requested(s1n2_context_t *ctx) {
    if (!ctx) {
        LOG_ERROR("ics_state_mark_amf_ics_requested: Invalid context\n");
        return -1;
    }

    ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
    if (!ue_map) {
        LOG_WARN("ics_state_mark_amf_ics_requested: No UE mapping found\n");
        return -1;
    }

    ue_map->amf_ics_requested = true;
    LOG_INFO("[ICS] Marked AMF ICS Request for UE (AMF-UE-ID=%ld)\n",
           ue_map->amf_ue_ngap_id);

    return 0;
}

/**
 * Check if pending S1AP ICS Response is cached
 */
bool ics_state_has_pending_s1ap_ics(s1n2_context_t *ctx) {
    if (!ctx) return false;

    ue_id_mapping_t *ue_map = s1n2_context_find_recent_security(ctx);
    if (!ue_map) return false;

    return ue_map->has_pending_s1ap_ics && (ue_map->pending_s1ap_ics_len > 0);
}
