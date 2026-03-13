/**
 * @file cause_conversion.c
 * @brief S1AP↔NGAP Cause value conversion utilities
 *
 * Wireshark trace: S1AP/NGAP Cause IE
 *
 * Moved from src/cplane/protocol_builders.c — Phase 4 refactoring.
 * Public API preserved in include/internal/protocol_builders.h.
 */
#include <string.h>

#include "internal/protocol_builders.h"

/* S1AP / NGAP Cause headers */
#include "S1AP_Cause.h"
#include "NGAP_Cause.h"

void s1n2_copy_s1ap_cause_to_ngap(const S1AP_Cause_t *src, NGAP_Cause_t *dst) {
    if (!dst) return;
    memset(dst, 0, sizeof(*dst));
    dst->present = NGAP_Cause_PR_radioNetwork;
    dst->choice.radioNetwork = NGAP_CauseRadioNetwork_unspecified;
    if (!src) return;

    switch (src->present) {
        case S1AP_Cause_PR_radioNetwork:
            dst->present = NGAP_Cause_PR_radioNetwork;
            dst->choice.radioNetwork = src->choice.radioNetwork;
            break;
        case S1AP_Cause_PR_transport:
            dst->present = NGAP_Cause_PR_transport;
            dst->choice.transport = src->choice.transport;
            break;
        case S1AP_Cause_PR_nas:
            dst->present = NGAP_Cause_PR_nas;
            dst->choice.nas = src->choice.nas;
            break;
        case S1AP_Cause_PR_protocol:
            dst->present = NGAP_Cause_PR_protocol;
            dst->choice.protocol = src->choice.protocol;
            break;
        case S1AP_Cause_PR_misc:
            dst->present = NGAP_Cause_PR_misc;
            dst->choice.misc = src->choice.misc;
            break;
        default:
            break;
    }
}

long s1n2_get_s1ap_cause_value(const S1AP_Cause_t *cause) {
    if (!cause) return -1;
    switch (cause->present) {
        case S1AP_Cause_PR_radioNetwork: return cause->choice.radioNetwork;
        case S1AP_Cause_PR_transport:    return cause->choice.transport;
        case S1AP_Cause_PR_nas:          return cause->choice.nas;
        case S1AP_Cause_PR_protocol:     return cause->choice.protocol;
        case S1AP_Cause_PR_misc:         return cause->choice.misc;
        default:                         return -1;
    }
}
