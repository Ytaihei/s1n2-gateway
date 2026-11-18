#include "s1n2_log.h"
/**
 * @file auth_config.c
 * @brief Authentication configuration loading
 *
 * YAML configuration file, .env file, and environment variable based
 * subscriber configuration loading.
 */
#define _GNU_SOURCE
#include "auth_config.h"
#include "subscriber_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <yaml.h>

#define LOG_TAG "[s1n2_auth]"

/* ------------------------------------------------------------------ */
/* Internal utility functions                                         */
/* ------------------------------------------------------------------ */

int s1n2_auth_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len) {
    if (!hex_str || !bytes) {
        return -1;
    }

    size_t hex_len = strlen(hex_str);
    if (hex_len != bytes_len * 2) {
        LOG_ERROR("%s ERROR: Invalid hex string length %zu, expected %zu\n",
                LOG_TAG, hex_len, bytes_len * 2);
        return -1;
    }

    for (size_t i = 0; i < bytes_len; i++) {
        sscanf(&hex_str[i * 2], "%2hhx", &bytes[i]);
    }

    return 0;
}

void s1n2_auth_bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex_str) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(&hex_str[i * 2], "%02x", bytes[i]);
    }
    hex_str[bytes_len * 2] = '\0';
}

static char* trim_whitespace_inplace(char *str) {
    if (!str) {
        return str;
    }

    while (*str && isspace((unsigned char)*str)) {
        str++;
    }

    if (*str == '\0') {
        return str;
    }

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return str;
}

static void strip_inline_comment(char *value) {
    if (!value) {
        return;
    }

    int quote = 0;
    for (char *p = value; *p; ++p) {
        if ((*p == '\"') || (*p == '\'')) {
            if (quote == 0) {
                quote = *p;
            } else if (quote == *p) {
                quote = 0;
            }
        } else if (*p == '#' && quote == 0) {
            if (p == value || isspace((unsigned char)*(p - 1))) {
                *p = '\0';
                break;
            }
        }
    }
}

static void strip_quotes_inplace(char *value) {
    if (!value) {
        return;
    }

    size_t len = strlen(value);
    if (len >= 2) {
        if ((value[0] == '\"' && value[len - 1] == '\"') ||
            (value[0] == '\'' && value[len - 1] == '\'')) {
            memmove(value, value + 1, len - 1);
            value[len - 2] = '\0';
        }
    }
}

/* ------------------------------------------------------------------ */
/* .env file import                                                   */
/* ------------------------------------------------------------------ */

int s1n2_auth_import_env_file(const char *path) {
    if (!path || !*path) {
        return 0;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        LOG_WARN("%s WARN: Unable to open env file %s: %s\n", LOG_TAG, path, strerror(errno));
        return -1;
    }

    char line[1024];
    int imported = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *cursor = trim_whitespace_inplace(line);
        if (*cursor == '\0' || *cursor == '#') {
            continue;
        }

        if (strncmp(cursor, "export", 6) == 0 && isspace((unsigned char)cursor[6])) {
            cursor += 6;
        }

        cursor = trim_whitespace_inplace(cursor);
        if (*cursor == '\0' || *cursor == '#') {
            continue;
        }

        char *eq = strchr(cursor, '=');
        if (!eq) {
            continue;
        }

        *eq = '\0';
        char *key = trim_whitespace_inplace(cursor);
        char *value = trim_whitespace_inplace(eq + 1);

        if (*key == '\0') {
            continue;
        }

        strip_inline_comment(value);
        value = trim_whitespace_inplace(value);
        strip_quotes_inplace(value);

        if (*value == '\0') {
            continue;
        }

        if (getenv(key)) {
            continue;
        }

        if (setenv(key, value, 0) == 0) {
            imported++;
        }
    }

    fclose(fp);

    if (imported > 0) {
        LOG_INFO("%s INFO: Imported %d environment variables from %s\n", LOG_TAG, imported, path);
    }

    return imported;
}

/* ------------------------------------------------------------------ */
/* Environment-variable based loading                                 */
/* ------------------------------------------------------------------ */

/* Forward declaration — implemented in subscriber_db.c */
extern int s1n2_auth_register_subscriber(s1n2_auth_context_t *auth_ctx,
                                         const char *imsi,
                                         const char *ki_hex,
                                         const char *opc_hex,
                                         const char *op_hex,
                                         const char *source_label);

int s1n2_auth_load_from_env(s1n2_auth_context_t *auth_ctx) {
    if (!auth_ctx) {
        return -1;
    }

    int loaded = 0;
    int max_entries = 32;
    const char *max_env = getenv("AUTH_ENV_MAX_UE");
    if (max_env && *max_env) {
        int candidate = atoi(max_env);
        if (candidate > 0 && candidate < 256) {
            max_entries = candidate;
        }
    }

    for (int idx = 1; idx <= max_entries; ++idx) {
        char imsi_key[32];
        snprintf(imsi_key, sizeof(imsi_key), "UE%d_IMSI", idx);
        const char *imsi = getenv(imsi_key);
        if (!imsi || !*imsi) {
            continue;
        }

        char ki_key[32];
        char opc_key[32];
        char op_key[32];
        snprintf(ki_key, sizeof(ki_key), "UE%d_KI", idx);
        snprintf(opc_key, sizeof(opc_key), "UE%d_OPC", idx);
        snprintf(op_key, sizeof(op_key), "UE%d_OP", idx);

        const char *ki_hex = getenv(ki_key);
        if (!ki_hex || !*ki_hex) {

            continue;
        }

        const char *opc_hex = getenv(opc_key);
        const char *op_hex = getenv(op_key);

        if (s1n2_auth_register_subscriber(auth_ctx, imsi, ki_hex, opc_hex, op_hex, imsi_key) > 0) {
            loaded++;
        }
    }

    const char *single_imsi = getenv("UE_IMSI");
    if (single_imsi && *single_imsi) {
        const char *single_ki = getenv("UE_KI");
        const char *single_opc = getenv("UE_OPC");
        const char *single_op = getenv("UE_OP");
        if (single_ki && *single_ki) {
            if (s1n2_auth_register_subscriber(auth_ctx, single_imsi, single_ki, single_opc, single_op, "UE_IMSI") > 0) {
                loaded++;
            }
        } else {

        }
    }

    const char *fallback_imsi = getenv("S1N2_FALLBACK_IMSI");
    if (fallback_imsi && *fallback_imsi) {
        const char *fallback_ki = getenv("S1N2_FALLBACK_KI");
        const char *fallback_opc = getenv("S1N2_FALLBACK_OPC");
        const char *fallback_op = getenv("S1N2_FALLBACK_OP");
        if (fallback_ki && *fallback_ki) {
            if (s1n2_auth_register_subscriber(auth_ctx, fallback_imsi, fallback_ki, fallback_opc, fallback_op, "S1N2_FALLBACK_IMSI") > 0) {
                loaded++;
            }
        }
    }

    return loaded;
}

/* ------------------------------------------------------------------ */
/* YAML configuration loading                                        */
/* ------------------------------------------------------------------ */

int s1n2_auth_load_keys(s1n2_auth_context_t *auth_ctx, const char *config_file) {
    if (!auth_ctx || !config_file) {
        LOG_ERROR("%s ERROR: NULL parameter\n", LOG_TAG);
        return -1;
    }

    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        LOG_ERROR("%s ERROR: Cannot open config file: %s\n", LOG_TAG, config_file);
        return -1;
    }

    yaml_parser_t parser;
    yaml_event_t event;

    if (!yaml_parser_initialize(&parser)) {
        LOG_ERROR("%s ERROR: Failed to initialize YAML parser\n", LOG_TAG);
        fclose(fp);
        return -1;
    }

    yaml_parser_set_input_file(&parser, fp);

    int in_subscribers = 0;
    int in_subscriber = 0;
    int subscriber_index = -1;
    char current_key[32] = {0};

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            LOG_ERROR("%s ERROR: YAML parse error\n", LOG_TAG);
            break;
        }

        switch (event.type) {
            case YAML_SCALAR_EVENT: {
                const char *value = (const char *)event.data.scalar.value;

                if (strcmp(value, "subscribers") == 0) {
                    in_subscribers = 1;
                } else if (strcmp(value, "res_star_kdf_mode") == 0) {
                    strncpy(current_key, "kdf_mode", sizeof(current_key) - 1);
                } else if (strcmp(current_key, "kdf_mode") == 0) {
                    if (strcmp(value, "standard") == 0) {
                        auth_ctx->res_star_kdf_mode = RES_STAR_KDF_STANDARD;

                    } else if (strcmp(value, "open5gs_compat") == 0) {
                        auth_ctx->res_star_kdf_mode = RES_STAR_KDF_OPEN5GS_COMPAT;
                        LOG_INFO("%s INFO: RES*/XRES* KDF mode: OPEN5GS_COMPAT (CK||IK-based, matches Open5GS v2.7.2 bug)\n", LOG_TAG);
                    } else {
                        LOG_WARN("%s WARNING: Unknown res_star_kdf_mode '%s', using 'standard'\n", LOG_TAG, value);
                        auth_ctx->res_star_kdf_mode = RES_STAR_KDF_STANDARD;
                    }
                    current_key[0] = '\0';
                } else if (strcmp(value, "xor_to_milenage_conversion") == 0) {
                    strncpy(current_key, "xor_conversion", sizeof(current_key) - 1);
                } else if (strcmp(current_key, "xor_conversion") == 0) {
                    if (strcmp(value, "true") == 0 || strcmp(value, "yes") == 0 || strcmp(value, "1") == 0) {
                        auth_ctx->xor_to_milenage_conversion = true;
                        LOG_INFO("%s INFO: XOR→Milenage conversion ENABLED\n", LOG_TAG);
                    } else {
                        auth_ctx->xor_to_milenage_conversion = false;
                    }
                    current_key[0] = '\0';
                } else if (in_subscribers && current_key[0] == '\0') {
                    strncpy(current_key, value, sizeof(current_key) - 1);
                } else if (in_subscriber && current_key[0] != '\0') {
                    if (subscriber_index >= 0 && subscriber_index < 32) {
                        s1n2_subscriber_keys_t *sub = &auth_ctx->subscribers[subscriber_index];

                        if (strcmp(current_key, "imsi") == 0) {
                            strncpy(sub->imsi, value, sizeof(sub->imsi) - 1);

                        } else if (strcmp(current_key, "ki") == 0) {
                            s1n2_auth_hex_to_bytes(value, sub->ki, 16);
                        } else if (strcmp(current_key, "opc") == 0) {
                            if (s1n2_auth_hex_to_bytes(value, sub->opc, 16) == 0) {

                                sub->configured = true;
                            }
                        }
                    }
                    current_key[0] = '\0';
                }
                break;
            }

            case YAML_SEQUENCE_START_EVENT:
                if (in_subscribers) {
                    in_subscriber = 1;
                }
                break;

            case YAML_MAPPING_START_EVENT:
                if (in_subscriber) {
                    subscriber_index++;
                    if (subscriber_index < 32) {
                        memset(&auth_ctx->subscribers[subscriber_index], 0,
                               sizeof(s1n2_subscriber_keys_t));
                    }
                }
                break;

            case YAML_MAPPING_END_EVENT:
                if (in_subscriber && subscriber_index >= 0) {
                    auth_ctx->subscriber_count = subscriber_index + 1;
                }
                break;

            case YAML_SEQUENCE_END_EVENT:
                in_subscriber = 0;
                break;

            default:
                break;
        }

        if (event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }
    } while (event.type != YAML_STREAM_END_EVENT);

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fp);

    LOG_INFO("%s INFO: Loaded %d subscribers\n", LOG_TAG, auth_ctx->subscriber_count);
    return auth_ctx->subscriber_count > 0 ? 0 : -1;
}
