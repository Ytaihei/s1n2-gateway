#include "s1n2_log.h"
/**
 * @file auth_init.c
 * @brief Authentication context initialization and cleanup
 *
 * Orchestrates configuration loading from all sources
 * (YAML, .env files, environment variables) and context lifecycle.
 */
#define _GNU_SOURCE
#include "subscriber_auth.h"
#include "config/auth_config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOG_TAG "[s1n2_auth]"

/* ------------------------------------------------------------------ */
/* Initialization                                                     */
/* ------------------------------------------------------------------ */

int s1n2_auth_init(s1n2_auth_context_t *auth_ctx, const char *config_file) {
    if (!auth_ctx) {
        LOG_ERROR("%s ERROR: NULL authentication context\n", LOG_TAG);
        return -1;
    }

    memset(auth_ctx, 0, sizeof(s1n2_auth_context_t));
    auth_ctx->enabled = true;
    auth_ctx->audit_logging = true;
    auth_ctx->auto_clear_keys = false;
    auth_ctx->max_cache_time = 300; /* 5 minutes */
    auth_ctx->res_star_kdf_mode = RES_STAR_KDF_STANDARD; /* Default: TS 33.501 compliant */

    int total_sources = 0;

    if (config_file && *config_file) {
        if (s1n2_auth_load_keys(auth_ctx, config_file) == 0) {
            total_sources++;
        } else {
            LOG_WARN("%s WARN: Falling back to environment-based subscriber configuration\n", LOG_TAG);
        }
    }

    const char *candidate_files[6] = {0};
    size_t candidate_count = 0;

    const char *env_override = getenv("AUTH_ENV_FILE");
    if (env_override && *env_override) {
        candidate_files[candidate_count++] = env_override;
    }

    const char *defaults[] = {
        ".env_s1n2",
        "/config/.env_s1n2",
        "/etc/s1n2/.env_s1n2",
        NULL
    };

    for (size_t i = 0; defaults[i] && candidate_count < (sizeof(candidate_files) / sizeof(candidate_files[0])); ++i) {
        bool duplicate = false;
        for (size_t j = 0; j < candidate_count; ++j) {
            if (candidate_files[j] && strcmp(candidate_files[j], defaults[i]) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            candidate_files[candidate_count++] = defaults[i];
        }
    }

    for (size_t i = 0; i < candidate_count; ++i) {
        const char *path = candidate_files[i];
        if (!path || !*path) {
            continue;
        }
        if (access(path, R_OK) != 0) {
            continue;
        }
        int imported = s1n2_auth_import_env_file(path);
        if (imported > 0) {
            total_sources++;
        }
    }

    int env_loaded = s1n2_auth_load_from_env(auth_ctx);
    if (env_loaded > 0) {
        total_sources++;
    }

    if (auth_ctx->subscriber_count == 0) {
        LOG_ERROR("%s ERROR: No subscriber authentication keys available after initialization\n", LOG_TAG);
        return -1;
    }

    LOG_INFO("%s INFO: Authentication context initialized with %d subscribers (%d source(s))\n",
           LOG_TAG, auth_ctx->subscriber_count, total_sources);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Cleanup                                                            */
/* ------------------------------------------------------------------ */

void s1n2_auth_cleanup(s1n2_auth_context_t *auth_ctx) {
    if (!auth_ctx) {
        return;
    }

    /* Clear sensitive key material */
    memset(auth_ctx->subscribers, 0, sizeof(auth_ctx->subscribers));
    memset(auth_ctx->auth_cache, 0, sizeof(auth_ctx->auth_cache));

    LOG_INFO("%s INFO: Cleaned up authentication context\n", LOG_TAG);
}
