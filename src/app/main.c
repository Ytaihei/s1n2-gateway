/**
 * @file main.c
 * @brief s1n2-converter entry point
 *
 * Signal setup, environment configuration, subsystem initialization,
 * and event loop invocation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "app_common.h"
#include "transport/sctp_transport.h"
#include "transport/udp_transport.h"
#include "event_loop.h"
#include "subscriber_auth.h"
#include "gtp_tunnel.h"

static void handle_signal(int signum) {
    (void)signum;
    g_should_terminate = 1;
}

/* Exit 0 if SCTP has >=2 associations (eNB<->s1n2 and s1n2<->AMF), else exit 1 */
static int run_healthcheck(void) {
    FILE *f = fopen("/proc/net/sctp/assocs", "r");
    if (!f) {
        fprintf(stderr, "healthcheck: cannot open /proc/net/sctp/assocs\n");
        return 1;
    }
    int count = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "<->"))
            count++;
    }
    fclose(f);
    if (count < 2) {
        fprintf(stderr, "SCTP associations not fully up (addr lines=%d)\n", count);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "--healthcheck") == 0)
        return run_healthcheck();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    /* Startup delay */
    const char* startup_delay_env = getenv("STARTUP_DELAY");
    if (startup_delay_env && *startup_delay_env) {
        int delay = atoi(startup_delay_env);
        if (delay > 0) {
            log_info("Startup delay requested: %d seconds", delay);
            sleep(delay);
        }
    }

    /* Read configuration from environment */
    const char* s1c_bind_addr  = app_getenv_default("S1C_BIND_ADDR", "0.0.0.0");
    const int   s1c_port       = atoi(app_getenv_default("S1C_PORT", "36412"));
    const char* s1u_bind_addr  = app_getenv_default("S1U_BIND_ADDR", "0.0.0.0");
    const int   s1u_port       = atoi(app_getenv_default("S1U_PORT", "2152"));
    const char* n2_remote_addr = app_getenv_default("N2_REMOTE_ADDR", app_getenv_default("AMF_IP", "172.24.0.12"));
    const int   n2_remote_port = atoi(app_getenv_default("N2_REMOTE_PORT", "38412"));
    const char* n3_remote_addr = app_getenv_default("N3_REMOTE_ADDR", app_getenv_default("UPF_IP", "172.24.0.21"));
    const int   n3_remote_port = atoi(app_getenv_default("N3_REMOTE_PORT", "2152"));

    log_info("s1n2-converter start");
    log_info("S1C_BIND=%s:%d, S1U_BIND=%s:%d", s1c_bind_addr, s1c_port, s1u_bind_addr, s1u_port);
    log_info("N2_REMOTE=%s:%d, N3_REMOTE=%s:%d", n2_remote_addr, n2_remote_port, n3_remote_addr, n3_remote_port);

    /* Initialize converter context */
    s1n2_init_context(&g_ctx);

    /* Initialize authentication */
    const char* auth_config = app_getenv_default("AUTH_CONFIG_FILE", "/config/auth_keys.yaml");
    log_info("Loading authentication keys from: %s", auth_config);

    s1n2_auth_context_t *auth_ctx = calloc(1, sizeof(s1n2_auth_context_t));
    if (!auth_ctx) {
        log_error("Failed to allocate authentication context");
        return 1;
    }

    if (s1n2_auth_init(auth_ctx, auth_config) != 0) {
        log_error("Failed to initialize authentication context - RES* computation will not be available");
        log_error("Converter will fall back to zero-padding (authentication may fail)");
        free(auth_ctx);
        auth_ctx = NULL;
    } else {
        log_info("Authentication context initialized with %d subscribers", auth_ctx->subscriber_count);
        s1n2_register_auth_context(&g_ctx, auth_ctx);
    }

    /* Initialize GTP-U TEID manager */
    if (gtp_tunnel_init() != 0) {
        log_error("Failed to initialize GTP-U TEID manager");
        if (auth_ctx) {
            s1n2_auth_cleanup(auth_ctx);
            free(auth_ctx);
        }
        return 1;
    }

    printf("[INFO] s1n2-converter: E-RAB management initialized - capacity: %d contexts, next PDU Session ID: %u\n",
           16, g_ctx.next_pdu_session_id);
    fflush(stdout);

    /* Initialize transports */
    if (sctp_transport_init_s1c(&g_ctx, s1c_bind_addr, s1c_port) != 0) return 1;
    if (sctp_transport_init_n2(&g_ctx, n2_remote_addr, n2_remote_port) != 0) return 1;
    if (udp_transport_init(&g_ctx, s1u_bind_addr, s1u_port, n3_remote_addr, n3_remote_port) != 0) return 1;

    log_info("listening S1C on %s:%d; forwarding N2 to %s:%d", s1c_bind_addr, s1c_port, n2_remote_addr, n2_remote_port);
    log_info("listening S1U on %s:%d; forwarding N3 to %s:%d", s1u_bind_addr, s1u_port, n3_remote_addr, n3_remote_port);

    /* Run event loop */
    event_loop_run(&g_ctx, n2_remote_addr, n2_remote_port);

    /* Cleanup */
    if (g_ctx.auth_ctx) {
        s1n2_auth_cleanup((s1n2_auth_context_t*)g_ctx.auth_ctx);
        free(g_ctx.auth_ctx);
        g_ctx.auth_ctx = NULL;
    }

    s1n2_cleanup_context(&g_ctx);
    log_info("s1n2-converter stop");
    return 0;
}


