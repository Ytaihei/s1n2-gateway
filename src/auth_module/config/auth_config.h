/**
 * @file auth_config.h
 * @brief Authentication configuration loading API
 *
 * YAML/env file/environment variable からの認証設定ロード機能。
 */
#ifndef S1N2_AUTH_CONFIG_H
#define S1N2_AUTH_CONFIG_H

#include "subscriber_auth.h"

/**
 * @brief Load subscriber keys from YAML configuration file
 *
 * @param auth_ctx Authentication context
 * @param config_file Path to YAML configuration file
 * @return 0 on success, -1 on error
 */
int s1n2_auth_load_keys(s1n2_auth_context_t *auth_ctx, const char *config_file);

/**
 * @brief Load subscriber keys from environment variables
 *
 * Reads UE{n}_IMSI, UE{n}_KI, UE{n}_OPC, UE{n}_OP environment variables.
 *
 * @param auth_ctx Authentication context
 * @return Number of subscribers loaded, or negative on error
 */
int s1n2_auth_load_from_env(s1n2_auth_context_t *auth_ctx);

/**
 * @brief Import environment variables from a .env file
 *
 * @param path Path to .env file
 * @return Number of variables imported, or negative on error
 */
int s1n2_auth_import_env_file(const char *path);

/* Internal utility (shared with subscriber_db) */
int s1n2_auth_hex_to_bytes(const char *hex_str, uint8_t *bytes, size_t bytes_len);
void s1n2_auth_bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex_str);

#endif /* S1N2_AUTH_CONFIG_H */
