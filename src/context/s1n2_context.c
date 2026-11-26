#include "s1n2_log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "s1n2_context_internal.h"

static s1n2_auth_context_t *g_shared_auth_ctx = NULL;

#define S1N2_TAU_GUARD_SECS 60

static long s1n2_context_tau_guard_age(const ue_id_mapping_t *ue_map) {
    if (!ue_map || ue_map->tau_start_time == 0) {
        return -1;
    }
    time_t now = time(NULL);
    if (now < ue_map->tau_start_time) {
        return 0;
    }
    return (long)(now - ue_map->tau_start_time);
}

void s1n2_context_trace_tau_flags(const ue_id_mapping_t *ue_map, const char *label) {
    if (!ue_map) {
        return;
    }
    if (!label) {
        label = "tau";
    }
    long age = s1n2_context_tau_guard_age(ue_map);
    LOG_INFO("[TAU] %s: RAN=%ld AMF=%ld in_tau=%d preserve_teid=%d guard_age=%lds\n",
           label,
           ue_map->ran_ue_ngap_id,
           ue_map->amf_ue_ngap_id,
           ue_map->in_tau_procedure ? 1 : 0,
           ue_map->preserve_teid_mapping ? 1 : 0,
           (age >= 0) ? age : -1L);

}

void s1n2_register_auth_context(s1n2_context_t *ctx, s1n2_auth_context_t *auth_ctx) {
    if (ctx) {
        ctx->auth_ctx = auth_ctx;
    }
    g_shared_auth_ctx = auth_ctx;
}

s1n2_auth_context_t *s1n2_context_get_shared_auth(void) {
    return g_shared_auth_ctx;
}

static ue_id_mapping_t *s1n2_context_alloc_mapping(s1n2_context_t *ctx) {
    if (!ctx) return NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (!entry->in_use) {
            memset(entry, 0, sizeof(*entry));
            entry->in_use = true;
            entry->enb_ue_s1ap_id = -1;
            entry->mme_ue_s1ap_id = -1;
            entry->ran_ue_ngap_id = -1;
            entry->amf_ue_ngap_id = -1;
            entry->created_time = time(NULL);
            entry->last_update = entry->created_time;

            // Initialize 5G NAS security counters
            entry->nas_ul_count_5g = 0;
            entry->has_sent_smc = false;

            // Initialize InitialContextSetup tracking
            entry->ics_sent = false;
            entry->ics_sent_time = 0;
            entry->ics_e_rab_id = 0;
            entry->ics_completed = false;
            entry->ics_failed = false;
            entry->ics_attempts = 0;

            if (ctx->num_ue_mappings < S1N2_MAX_UE_MAPPINGS) {
                ctx->num_ue_mappings++;
            }
            return entry;
        }
    }
    return NULL;
}

ue_id_mapping_t *s1n2_context_find_mapping_by_enb(s1n2_context_t *ctx, long enb_id) {
    if (!ctx) return NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (entry->in_use && entry->enb_ue_s1ap_id == enb_id) {
            entry->last_update = time(NULL);
            return entry;
        }
    }
    return NULL;
}

ue_id_mapping_t *s1n2_context_find_mapping_by_ran(s1n2_context_t *ctx, long ran_id) {
    if (!ctx) return NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (entry->in_use && entry->ran_ue_ngap_id == ran_id) {
            entry->last_update = time(NULL);
            return entry;
        }
    }
    return NULL;
}

ue_id_mapping_t *s1n2_context_find_mapping_by_amf(s1n2_context_t *ctx, long amf_id) {
    if (!ctx) return NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (entry->in_use && entry->amf_ue_ngap_id == amf_id) {
            entry->last_update = time(NULL);
            return entry;
        }
    }
    return NULL;
}

ue_id_mapping_t *s1n2_context_find_recent_security(s1n2_context_t *ctx) {
    if (!ctx) return NULL;
    ue_id_mapping_t *best = NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (!entry->in_use || !entry->has_security_mode) {
            continue;
        }
        if (!best || entry->last_update > best->last_update) {
            best = entry;
        }
    }
    return best;
}

ue_id_mapping_t *s1n2_context_find_mapping_with_cached_rand(s1n2_context_t *ctx) {
    if (!ctx) return NULL;
    for (size_t i = 0; i < S1N2_MAX_UE_MAPPINGS; ++i) {
        ue_id_mapping_t *entry = &ctx->ue_mappings[i];
        if (entry->in_use && entry->rand_cached) {
            return entry;
        }
    }
    return NULL;
}

ue_id_mapping_t *s1n2_context_create_mapping(s1n2_context_t *ctx,
                                             long ran_id,
                                             long amf_id,
                                             long enb_id,
                                             long mme_id) {
    if (!ctx) return NULL;

    ue_id_mapping_t *entry = s1n2_context_alloc_mapping(ctx);
    if (!entry) {
        LOG_WARN("UE mapping table full, cannot create new mapping\n");

        return NULL;
    }

    entry->ran_ue_ngap_id = ran_id;
    entry->amf_ue_ngap_id = amf_id;
    entry->enb_ue_s1ap_id = enb_id;
    entry->mme_ue_s1ap_id = mme_id;
    entry->last_update = time(NULL);

    LOG_DEBUG("Created new UE mapping: RAN=%ld, AMF=%ld, ENB=%ld, MME=%ld\n",
           ran_id, amf_id, enb_id, mme_id);

    return entry;
}

ue_id_mapping_t *s1n2_context_ensure_mapping_for_enb(s1n2_context_t *ctx, long enb_id) {
    if (!ctx || enb_id < 0) return NULL;
    ue_id_mapping_t *entry = s1n2_context_find_mapping_by_enb(ctx, enb_id);
    if (entry) return entry;

    entry = s1n2_context_alloc_mapping(ctx);
    if (!entry) {
        LOG_WARN("UE mapping table full, cannot track ENB UE ID %ld\n", enb_id);

        return NULL;
    }

    entry->enb_ue_s1ap_id = enb_id;
    entry->ran_ue_ngap_id = (enb_id > 0) ? enb_id : ctx->next_ran_ue_ngap_id++;
    entry->mme_ue_s1ap_id = -1;
    entry->amf_ue_ngap_id = -1;
    entry->last_update = time(NULL);

    if (entry->ran_ue_ngap_id >= ctx->next_ran_ue_ngap_id) {
        ctx->next_ran_ue_ngap_id = entry->ran_ue_ngap_id + 1;
    }

    LOG_DEBUG("Created UE mapping: ENB=%ld -> RAN=%ld\n",
           entry->enb_ue_s1ap_id, entry->ran_ue_ngap_id);

    return entry;
}

long s1n2_context_generate_ran_ue_ngap_id(s1n2_context_t *ctx, long preferred_id) {
    if (!ctx) {
        return (preferred_id > 0) ? preferred_id : -1;
    }

    long assigned = preferred_id;
    if (assigned <= 0) {
        assigned = ctx->next_ran_ue_ngap_id++;
    } else if (assigned >= ctx->next_ran_ue_ngap_id) {
        ctx->next_ran_ue_ngap_id = assigned + 1;
    }

    if (ctx->next_ran_ue_ngap_id <= 0) {
        ctx->next_ran_ue_ngap_id = assigned + 1;
        if (ctx->next_ran_ue_ngap_id <= 0) {
            ctx->next_ran_ue_ngap_id = 1;
        }
    }

    return assigned;
}

int s1n2_init_context(s1n2_context_t *ctx) {
    if (!ctx) return -1;
    memset(ctx, 0, sizeof(*ctx));
    ctx->s1c_fd = ctx->n2_fd = ctx->s1u_fd = ctx->n3_fd = -1;
    ctx->next_n3_teid = 0x1000;
    ctx->next_pdu_session_id = 1;  // Start PDU Session IDs from 1
    ctx->ngsetup_sent = false;
    ctx->has_pending_s1setup = false;  // Initialize pending S1Setup state

    memset(ctx->ue_mappings, 0, sizeof(ctx->ue_mappings));
    ctx->num_ue_mappings = 0;
    ctx->next_ran_ue_ngap_id = 1;

    // Initialize E-RAB contexts
    for (int i = 0; i < 16; i++) {
        ctx->e_rab_contexts[i].is_active = false;
    }
    ctx->num_e_rab_contexts = 0;

    LOG_DEBUG("s1n2_init_context: E-RAB management initialized - %d contexts available, "
           "starting PDU Session ID: %u\n",
           16, ctx->next_pdu_session_id);

    return 0;
}

void s1n2_cleanup_context(s1n2_context_t *ctx) {
    if (!ctx) return;
    if (ctx->s1c_fd >= 0) close(ctx->s1c_fd);
    if (ctx->n2_fd >= 0) close(ctx->n2_fd);
    if (ctx->s1u_fd >= 0) close(ctx->s1u_fd);
    if (ctx->n3_fd >= 0) close(ctx->n3_fd);
}

void s1n2_context_mark_tau_start(ue_id_mapping_t *ue_map) {
    if (!ue_map) {
        return;
    }
    ue_map->in_tau_procedure = true;
    ue_map->preserve_teid_mapping = true;
    ue_map->tau_start_time = time(NULL);
    s1n2_context_trace_tau_flags(ue_map, "tau-start");
}

void s1n2_context_mark_tau_complete(ue_id_mapping_t *ue_map) {
    if (!ue_map) {
        return;
    }
    if (!ue_map->in_tau_procedure && !ue_map->preserve_teid_mapping) {
        return;
    }
    ue_map->in_tau_procedure = false;
    ue_map->preserve_teid_mapping = false;
    ue_map->tau_start_time = 0;
    s1n2_context_trace_tau_flags(ue_map, "tau-complete");
}

bool s1n2_context_should_preserve_teid(const ue_id_mapping_t *ue_map) {
    return ue_map && ue_map->preserve_teid_mapping;
}

void s1n2_context_cache_registration_result(ue_id_mapping_t *ue_map,
                                            const uint8_t *value,
                                            uint8_t len) {
    if (!ue_map || !value || len == 0) {
        return;
    }
    uint8_t copy = len;
    if (copy > sizeof(ue_map->last_registration_result)) {
        copy = sizeof(ue_map->last_registration_result);
    }
    memcpy(ue_map->last_registration_result, value, copy);
    ue_map->last_registration_result_len = copy;
    ue_map->has_last_registration_result = true;
    s1n2_context_cache_access_type(ue_map, value[0] & 0x07);
}

void s1n2_context_cache_5g_guti(ue_id_mapping_t *ue_map,
                                const uint8_t *value,
                                uint16_t len) {
    if (!ue_map || !value || len == 0) {
        return;
    }
    uint16_t copy = len;
    if (copy > sizeof(ue_map->last_5g_guti)) {
        copy = sizeof(ue_map->last_5g_guti);
        LOG_WARN("5G-GUTI length %u exceeds cache buffer, truncating to %zu bytes\n",
               len, sizeof(ue_map->last_5g_guti));
    }
    memcpy(ue_map->last_5g_guti, value, copy);
    ue_map->last_5g_guti_len = (uint8_t)copy;
    ue_map->has_last_5g_guti = true;
}

void s1n2_context_cache_access_type(ue_id_mapping_t *ue_map, uint8_t access_type) {
    if (!ue_map) {
        return;
    }
    ue_map->has_last_access_type = true;
    ue_map->last_5gs_access_type = access_type & 0x07;
}
