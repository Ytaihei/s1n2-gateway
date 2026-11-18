#include "s1n2_log.h"
/**
 * @file sctp_transport.c
 * @brief SCTP transport initialization and connection management
 *
 * Handles S1C (SCTP server for eNB) and N2 (SCTP client to AMF)
 * socket creation, binding, connection, and retry logic.
 *
 * Wireshark correspondence:
 *   - SCTP INIT / INIT_ACK / COOKIE_ECHO / COOKIE_ACK
 *   - SCTP PPID=18 (S1AP), PPID=60 (NGAP)
 */
#include "sctp_transport.h"
#include "app/app_common.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* S1C — SCTP server (one-to-one)                                     */
/* ------------------------------------------------------------------ */

int sctp_transport_init_s1c(s1n2_context_t *ctx, const char *bind_addr, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
        log_error("socket(SCTP) failed: %s", strerror(errno));
        return -1;
    }

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
        log_error("inet_pton(S1C) failed for %s", bind_addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("bind(S1C) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        log_error("listen(S1C) failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    app_set_nonblocking(fd);

    ctx->s1c_fd = fd;
    ctx->s1c_addr = addr;

    return 0;
}

/* ------------------------------------------------------------------ */
/* N2 — SCTP client (to AMF)                                          */
/* ------------------------------------------------------------------ */

int sctp_transport_init_n2(s1n2_context_t *ctx, const char *remote_addr, int remote_port) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
        log_error("socket(N2 SCTP) failed: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)remote_port);
    if (inet_pton(AF_INET, remote_addr, &addr.sin_addr) != 1) {
        log_error("inet_pton(N2) failed for %s", remote_addr);
        close(fd);
        return -1;
    }

    app_set_nonblocking(fd);

    ctx->n2_connected = false;
    ctx->n2_connection_attempted = false;
    ctx->n2_retry_time = time(NULL);

    int rc = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        log_error("connect(N2) initial attempt failed: %s", strerror(errno));
        ctx->n2_connection_attempted = false;
        ctx->n2_retry_time = time(NULL) + 5;
    } else {
        log_info("N2 connection initiated to %s:%d", remote_addr, remote_port);
        ctx->n2_connection_attempted = true;
    }

    ctx->n2_fd = fd;
    ctx->n2_addr = addr;

    return 0;
}

/* ------------------------------------------------------------------ */
/* N2 connection retry                                                */
/* ------------------------------------------------------------------ */

void sctp_transport_retry_n2(s1n2_context_t *ctx, const char *remote_addr, int remote_port) {
    time_t now = time(NULL);
    if (ctx->n2_connected || ctx->n2_connection_attempted || now < ctx->n2_retry_time) {
        return;
    }

    log_info("Retrying N2 connection to %s:%d", remote_addr, remote_port);
    close(ctx->n2_fd);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
        log_error("socket(N2 retry) failed: %s", strerror(errno));
        ctx->n2_retry_time = now + 5;
        return;
    }

    app_set_nonblocking(fd);

    int rc = connect(fd, (struct sockaddr*)&ctx->n2_addr, sizeof(ctx->n2_addr));
    if (rc < 0 && errno != EINPROGRESS) {
        log_error("connect(N2) retry failed: %s", strerror(errno));
        ctx->n2_connection_attempted = false;
        ctx->n2_retry_time = now + 5;
    } else {
        log_info("N2 connection retry initiated");
        ctx->n2_connection_attempted = true;
    }

    ctx->n2_fd = fd;
}

/* ------------------------------------------------------------------ */
/* Retry-send helper (poll + exponential backoff)                     */
/* ------------------------------------------------------------------ */

ssize_t sctp_retry_send(int fd, const void *data, size_t len, uint32_t ppid,
                        int max_wait_ms, const char *label) {
    int total_wait_ms = 0;
    int backoff_ms = 50;

    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLOUT, .revents = 0};
        int poll_ret = poll(&pfd, 1, backoff_ms);

        if (poll_ret > 0 && (pfd.revents & POLLOUT)) {
            ssize_t sent = sctp_sendmsg(fd, data, len,
                                        NULL, 0, htonl(ppid), 0, 0, 0, 0);
            if (sent == (ssize_t)len) {
                LOG_INFO("%s sent (%zd bytes, PPID=%u)\n", label, sent, ppid);

                return sent;
            }
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                /* transient — continue retrying within budget */
            } else {
                if (errno == EPIPE || errno == ECONNRESET) {
                    LOG_WARN("Connection broken during %s send (errno=%d: %s)\n",
                           label, errno, strerror(errno));
                } else {
                    LOG_ERROR("Failed to send %s via SCTP (ret=%zd, PPID=%u, errno=%d: %s)\n",
                           label, sent, ppid, errno, strerror(errno));
                }

                return -1;
            }
        } else if (poll_ret < 0 && errno != EINTR) {
            LOG_ERROR("poll() failed before %s send (errno=%d: %s)\n",
                   label, errno, strerror(errno));

            return -1;
        }

        total_wait_ms += backoff_ms;
        if (backoff_ms < 200) backoff_ms += 50;
        if (total_wait_ms >= max_wait_ms) {
            LOG_WARN("Socket not writable after %dms, deferring %s\n",
                   total_wait_ms, label);

            return -1;
        }
    }
}
