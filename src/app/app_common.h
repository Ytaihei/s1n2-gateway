/**
 * @file app_common.h
 * @brief Shared declarations for app module
 *
 * Logging utilities, helper functions, and global state
 * used across main, transport, and event loop modules.
 */
#ifndef S1N2_APP_COMMON_H
#define S1N2_APP_COMMON_H

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>
#include "s1n2_converter.h"

#define LOG_BUFFER_SIZE 1024

/* Global termination flag (set by signal handler) */
extern volatile sig_atomic_t g_should_terminate;

/* Global converter context */
extern s1n2_context_t g_ctx;

/* ------------------------------------------------------------------ */
/* Logging                                                            */
/* ------------------------------------------------------------------ */

#include "s1n2_log.h"
#define log_info(...) LOG_INFO(__VA_ARGS__)
#define log_error(...) LOG_ERROR(__VA_ARGS__)

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * @brief Set a file descriptor to non-blocking mode
 */
int app_set_nonblocking(int fd);

/**
 * @brief Get environment variable with default fallback
 */
const char* app_getenv_default(const char* key, const char* def);

#endif /* S1N2_APP_COMMON_H */
