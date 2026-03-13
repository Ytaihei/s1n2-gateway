/**
 * @file udp_transport.c
 * @brief UDP transport initialization for GTP-U
 *
 * S1-U (eNB ↔ Converter) and N3 (Converter ↔ UPF) socket setup.
 *
 * Wireshark correspondence:
 *   - UDP port 2152 (GTP-U: Echo, G-PDU)
 */
#include "udp_transport.h"
#include "app/app_common.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int udp_transport_init(s1n2_context_t *ctx,
                       const char *s1u_bind_addr, int s1u_port,
                       const char *n3_remote_addr, int n3_remote_port) {

    int one = 1;

    /* ---- S1-U socket ---- */
    int s1u_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (s1u_fd < 0) {
        log_error("socket(S1U UDP) failed: %s", strerror(errno));
        return -1;
    }
    setsockopt(s1u_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(s1u_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    struct sockaddr_in s1u_addr = {0};
    s1u_addr.sin_family = AF_INET;
    s1u_addr.sin_port = htons((uint16_t)s1u_port);
    if (inet_pton(AF_INET, s1u_bind_addr, &s1u_addr.sin_addr) != 1) {
        log_error("inet_pton(S1U) failed for %s", s1u_bind_addr);
        close(s1u_fd);
        return -1;
    }
    if (bind(s1u_fd, (struct sockaddr*)&s1u_addr, sizeof(s1u_addr)) < 0) {
        log_error("bind(S1U) failed: %s", strerror(errno));
        close(s1u_fd);
        return -1;
    }
    app_set_nonblocking(s1u_fd);

    /* ---- N3 socket ---- */
    int n3_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (n3_fd < 0) {
        log_error("socket(N3 UDP) failed: %s", strerror(errno));
        close(s1u_fd);
        return -1;
    }
    setsockopt(n3_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
    setsockopt(n3_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
    app_set_nonblocking(n3_fd);

    struct sockaddr_in n3_addr = {0};
    n3_addr.sin_family = AF_INET;
    n3_addr.sin_port = htons((uint16_t)n3_remote_port);
    if (inet_pton(AF_INET, n3_remote_addr, &n3_addr.sin_addr) != 1) {
        log_error("inet_pton(N3) failed for %s", n3_remote_addr);
        close(s1u_fd);
        close(n3_fd);
        return -1;
    }

    /* Bind N3 to same local port as S1-U (source port 2152) */
    struct sockaddr_in n3_local = {0};
    n3_local.sin_family = AF_INET;
    n3_local.sin_port = htons((uint16_t)s1u_port);
    n3_local.sin_addr = s1u_addr.sin_addr;
    if (bind(n3_fd, (struct sockaddr*)&n3_local, sizeof(n3_local)) < 0) {
        log_error("bind(N3 local) failed: %s", strerror(errno));
        /* Not fatal — outgoing packets may use ephemeral port */
    }

    /* Connect N3 to UPF so send() works without specifying destination */
    if (connect(n3_fd, (struct sockaddr*)&n3_addr, sizeof(n3_addr)) < 0) {
        log_error("connect(N3 UDP) failed: %s", strerror(errno));
        close(s1u_fd);
        close(n3_fd);
        return -1;
    }

    /* Detect actual local IP for AMF reporting */
    struct sockaddr_in local_n3_addr;
    socklen_t addr_len = sizeof(local_n3_addr);
    if (getsockname(n3_fd, (struct sockaddr*)&local_n3_addr, &addr_len) == 0) {
        s1u_addr.sin_addr.s_addr = local_n3_addr.sin_addr.s_addr;
        char local_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &local_n3_addr.sin_addr, local_ip_str, sizeof(local_ip_str));
        log_info("Detected local N3 IP: %s (will report this to AMF as uplink tunnel endpoint)", local_ip_str);
    } else {
        log_error("Failed to get local N3 address: %s", strerror(errno));
        log_error("Will report 0.0.0.0 to AMF (this may cause UPF errors)");
    }

    /* Store in context */
    ctx->s1u_fd = s1u_fd;
    ctx->n3_fd = n3_fd;
    ctx->s1u_addr = s1u_addr;
    ctx->n3_addr = n3_addr;

    return 0;
}
