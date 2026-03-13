/**
 * @file event_loop.c
 * @brief Main poll()-based event loop
 *
 * Multiplexes S1C (SCTP from eNB), N2 (SCTP to AMF),
 * S1U (UDP GTP-U uplink), and N3 (UDP GTP-U downlink).
 *
 * Wireshark correspondence:
 *   - S1AP messages (SCTP PPID=18) → s1n2_handle_s1c_message()
 *   - NGAP messages (SCTP PPID=60) → s1n2_handle_n2_message()
 *   - GTP-U (UDP port 2152)        → s1n2_handle_gtpu_message()
 */
#include "event_loop.h"
#include "transport/sctp_transport.h"
#include "app_common.h"
#include "gtp_header.h"
#include "gtp_tunnel.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/sctp.h>
#include <poll.h>
#include <time.h>

void event_loop_run(s1n2_context_t *ctx, const char *n2_remote_addr, int n2_remote_port) {
    int s1c_listen_fd = ctx->s1c_fd;  /* listening socket */
    int s1c_client_fd = -1;
    int s1u_peer_connected = 0;

    struct pollfd pfds[5];

    while (!g_should_terminate) {
        /* ---- N2 connection retry ---- */
        sctp_transport_retry_n2(ctx, n2_remote_addr, n2_remote_port);

        /* ---- Build pollfd array ---- */
        int idx = 0;
        pfds[idx].fd = s1c_listen_fd; pfds[idx].events = POLLIN; idx++;
        if (s1c_client_fd >= 0) {
            pfds[idx].fd = s1c_client_fd; pfds[idx].events = POLLIN; idx++;
        }
        pfds[idx].fd = ctx->s1u_fd; pfds[idx].events = POLLIN; idx++;
        pfds[idx].fd = ctx->n3_fd;  pfds[idx].events = POLLIN; idx++;
        pfds[idx].fd = ctx->n2_fd;  pfds[idx].events = POLLIN | POLLOUT; idx++;

        int ret = poll(pfds, idx, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            log_error("poll failed: %s", strerror(errno));
            break;
        }

        /* ---- Trace N2 socket events ---- */
        if (idx > 0 && pfds[idx-1].fd == ctx->n2_fd) {
            short n2_events = pfds[idx-1].revents;
            if (n2_events & (POLLERR | POLLHUP | POLLNVAL)) {
                log_error("N2 poll revents=0x%02x (attempted=%d, connected=%d)",
                          n2_events, ctx->n2_connection_attempted, ctx->n2_connected);
            } else if (!ctx->n2_connected && !ctx->n2_connection_attempted && n2_events) {
                log_info("N2 poll intermediate events=0x%02x while awaiting retry", n2_events);
            }
        }

        /* ---- Periodic GTP-U tunnel maintenance ---- */
        gtp_tunnel_maintenance();

        /* ---- Accept S1C client ---- */
        if (pfds[0].revents & POLLIN || s1c_client_fd < 0) {
            while (s1c_client_fd < 0) {
                struct sockaddr_in cli; socklen_t clilen = sizeof(cli);
                int cfd = accept(s1c_listen_fd, (struct sockaddr*)&cli, &clilen);
                if (cfd >= 0) {
                    app_set_nonblocking(cfd);
                    s1c_client_fd = cfd;
                    ctx->s1c_fd = cfd;
                    char ip[64];
                    inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
                    log_info("S1C accepted from %s:%d", ip, ntohs(cli.sin_port));
                    break;
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    else if (errno == EINTR) continue;
                    else {
                        log_error("S1C accept failed: %s", strerror(errno));
                        break;
                    }
                }
            }
        }

        /* ---- S1U → N3 (GTP-U uplink) ---- */
        int s1u_idx = (s1c_client_fd >= 0) ? 2 : 1;
        if (idx > s1u_idx && pfds[s1u_idx].fd == ctx->s1u_fd && (pfds[s1u_idx].revents & POLLIN)) {
            uint8_t buf[2048];
            struct sockaddr_in peer; socklen_t plen = sizeof(peer);
            ssize_t n = recvfrom(ctx->s1u_fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &plen);
            if (n > 0) {
                if (!s1u_peer_connected) {
                    if (connect(ctx->s1u_fd, (struct sockaddr*)&peer, sizeof(peer)) == 0) {
                        char ip[64];
                        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
                        log_info("S1U connected to eNB peer %s:%d", ip, ntohs(peer.sin_port));
                        s1u_peer_connected = 1;
                    } else {
                        log_error("connect(S1U UDP->eNB) failed: %s", strerror(errno));
                    }
                }
                s1n2_handle_gtpu_message(ctx, buf, (size_t)n);
            }
        }

        /* ---- N3 → S1U (GTP-U downlink) ---- */
        int n3_idx = s1u_idx + 1;
        if (idx > n3_idx && pfds[n3_idx].fd == ctx->n3_fd && (pfds[n3_idx].revents & POLLIN)) {
            uint8_t buf[2048];
            struct sockaddr_in peer; socklen_t plen = sizeof(peer);
            ssize_t n = recvfrom(ctx->n3_fd, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &plen);
            if (n > 0) {
                s1n2_handle_gtpu_message(ctx, buf, (size_t)n);
            }
        }

        /* ---- N2 readable (NGAP from AMF) ---- */
        int n2_idx = idx - 1;
        if (idx > 0 && pfds[n2_idx].fd == ctx->n2_fd && (pfds[n2_idx].revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t n = recv(ctx->n2_fd, buf, sizeof(buf), 0);
            if (n > 0) {
                s1n2_handle_n2_message(ctx, buf, (size_t)n);
            }
        }

        /* ---- N2 connection completion ---- */
        if (idx > 0 && pfds[n2_idx].fd == ctx->n2_fd && (pfds[n2_idx].revents & POLLOUT)) {
            if (!ctx->n2_connected && ctx->n2_connection_attempted) {
                int error = 0;
                socklen_t len = sizeof(error);
                if (getsockopt(ctx->n2_fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0 && error == 0) {
                    ctx->n2_connected = true;
                    ctx->n2_connection_attempted = true;
                    log_info("N2 connected to %s:%d", n2_remote_addr, n2_remote_port);

                    /* Send NGSetupRequest */
                    if (!ctx->ngsetup_sent) {
                        uint8_t ngbuf[2048]; size_t nglen = sizeof(ngbuf);
                        int enc = build_ngsetup_request_dynamic(ngbuf, &nglen);
                        if (enc > 0) {
                            ssize_t wn = sctp_sendmsg(ctx->n2_fd, ngbuf, (size_t)nglen,
                                                      NULL, 0, htonl(60), 0, 0, 0, 0);
                            if (wn == (ssize_t)nglen) {
                                log_info("Sent dynamic NGSetupRequest (%zu bytes, PPID=60)", nglen);
                                ctx->ngsetup_sent = true;
                            } else {
                                log_error("Failed to send NGSetupRequest via SCTP (ret=%zd, errno=%d)", wn, errno);
                            }
                        } else {
                            log_error("build_ngsetup_request_dynamic failed");
                        }
                    }
                } else {
                    log_error("N2 connection failed: %s (will retry in 5 seconds)", strerror(error));
                    ctx->n2_connection_attempted = false;
                    ctx->n2_retry_time = time(NULL) + 5;
                    close(ctx->n2_fd);
                    ctx->n2_fd = -1;
                }
            }
        }

        /* ---- S1C client readable (S1AP from eNB) ---- */
        if (s1c_client_fd >= 0) {
            for (int j = 0; j < idx; ++j) {
                if (pfds[j].fd == s1c_client_fd && (pfds[j].revents & POLLIN)) {
                    uint8_t buf[2048];
                    ssize_t n = recv(s1c_client_fd, buf, sizeof(buf), 0);
                    if (n > 0) {
                        log_info("S1C received %zd bytes", n);
                        s1n2_handle_s1c_message(ctx, buf, (size_t)n);
                    } else if (n == 0) {
                        log_info("S1C client closed");
                        close(s1c_client_fd);
                        s1c_client_fd = -1;
                        ctx->s1c_fd = -1;
                    } else if (n < 0) {
                        log_error("S1C recv failed: %s", strerror(errno));
                    }
                }
            }
        }
    }

    /* ---- Cleanup ---- */
    if (s1c_client_fd >= 0) close(s1c_client_fd);
}
