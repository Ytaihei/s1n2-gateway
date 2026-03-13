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

static inline void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buffer[LOG_BUFFER_SIZE];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    fprintf(stdout, "[INFO] %s\n", buffer);
    fflush(stdout);
}

static inline void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buffer[LOG_BUFFER_SIZE];
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    fprintf(stderr, "[ERROR] %s\n", buffer);
    fflush(stderr);
}

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
