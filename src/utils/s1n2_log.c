#include "s1n2_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int threshold = -1;
static const char *levels[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};

void s1n2_log_set_level(s1n2_log_level_t level) {
    threshold = level >= S1N2_LOG_ERROR && level <= S1N2_LOG_TRACE ? (int)level : S1N2_LOG_INFO;
}

bool s1n2_log_enabled(s1n2_log_level_t level) {
    if (level < S1N2_LOG_ERROR || level > S1N2_LOG_TRACE) return false;
    if (threshold < 0) {
        threshold = S1N2_LOG_INFO;
        const char *env = getenv("S1N2_LOG_LEVEL");
        for (int i = 0; env && i <= S1N2_LOG_TRACE; i++) {
            if (strcmp(env, levels[i]) == 0) threshold = i;
        }
    }
    return (int)level <= threshold;
}

void s1n2_log(s1n2_log_level_t level, const char *module, const char *fmt, ...) {
    if (!s1n2_log_enabled(level)) return;
    char message[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    size_t n = strlen(message);
    while (n && (message[n-1] == '\n' || message[n-1] == '\r')) message[--n] = 0;
    /* One event per line, including strings returned by external libraries. */
    for (size_t i = 0; i < n; i++) if (message[i] == '\n' || message[i] == '\r') message[i] = ' ';
    const char *name = strrchr(module, '/');
    fprintf(stderr, "[%s] [%s] %s\n", levels[level], name ? name + 1 : module, message);
}
