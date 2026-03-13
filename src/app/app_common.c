/**
 * @file app_common.c
 * @brief Shared global state and helper implementations for app module
 */
#include "app_common.h"
#include <fcntl.h>
#include <stdlib.h>

volatile sig_atomic_t g_should_terminate = 0;
s1n2_context_t g_ctx;

int app_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

const char* app_getenv_default(const char* key, const char* def) {
    const char* val = getenv(key);
    return (val && *val) ? val : def;
}
