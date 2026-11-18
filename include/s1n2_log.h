#ifndef S1N2_LOG_H
#define S1N2_LOG_H

#include <stdbool.h>
#include <stdarg.h>

typedef enum {
    S1N2_LOG_ERROR, S1N2_LOG_WARN, S1N2_LOG_INFO, S1N2_LOG_DEBUG, S1N2_LOG_TRACE
} s1n2_log_level_t;

/* S1N2_LOG_LEVEL defaults to INFO. Never pass keys, identities or packet bodies. */
bool s1n2_log_enabled(s1n2_log_level_t level);
void s1n2_log_set_level(s1n2_log_level_t level);
void s1n2_log(s1n2_log_level_t level, const char *module, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
#define LOG_ERROR(...) s1n2_log(S1N2_LOG_ERROR, __FILE__, __VA_ARGS__)
#define LOG_WARN(...) s1n2_log(S1N2_LOG_WARN, __FILE__, __VA_ARGS__)
#define LOG_INFO(...) s1n2_log(S1N2_LOG_INFO, __FILE__, __VA_ARGS__)
#define LOG_DEBUG(...) s1n2_log(S1N2_LOG_DEBUG, __FILE__, __VA_ARGS__)
#define LOG_TRACE(...) s1n2_log(S1N2_LOG_TRACE, __FILE__, __VA_ARGS__)
#endif
