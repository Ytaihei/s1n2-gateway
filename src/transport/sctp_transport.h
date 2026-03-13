/**
 * @file sctp_transport.h
 * @brief SCTP transport initialization API
 *
 * Wireshark correspondence:
 *   - SCTP INIT / INIT_ACK / COOKIE (association setup)
 *   - PPID 18 (S1AP), PPID 60 (NGAP)
 */
#ifndef S1N2_SCTP_TRANSPORT_H
#define S1N2_SCTP_TRANSPORT_H

#include "s1n2_converter.h"

/**
 * @brief Initialize S1C SCTP server (listening socket)
 *
 * @param ctx Converter context (s1c_fd, s1c_addr populated)
 * @param bind_addr Bind address string
 * @param port Bind port
 * @return 0 on success, -1 on error
 */
int sctp_transport_init_s1c(s1n2_context_t *ctx, const char *bind_addr, int port);

/**
 * @brief Initialize N2 SCTP client (to AMF)
 *
 * @param ctx Converter context (n2_fd, n2_addr populated)
 * @param remote_addr AMF address string
 * @param remote_port AMF port
 * @return 0 on success, -1 on error
 */
int sctp_transport_init_n2(s1n2_context_t *ctx, const char *remote_addr, int remote_port);

/**
 * @brief Retry N2 connection if not connected and retry timer has elapsed
 *
 * @param ctx Converter context
 * @param remote_addr AMF address for logging
 * @param remote_port AMF port for logging
 */
void sctp_transport_retry_n2(s1n2_context_t *ctx, const char *remote_addr, int remote_port);

/**
 * @brief Send data over SCTP with poll-based retry on transient errors
 *
 * Uses poll() with exponential backoff (50→200ms steps) to handle
 * EAGAIN / EWOULDBLOCK.  Returns as soon as the full message is sent
 * or an unrecoverable error / timeout occurs.
 *
 * @param fd          SCTP socket file descriptor
 * @param data        Data buffer to send
 * @param len         Length of data in bytes
 * @param ppid        SCTP PPID (18 = S1AP, 60 = NGAP)
 * @param max_wait_ms Maximum total wait time in milliseconds (typically 1500)
 * @param label       Human-readable label for log messages
 * @return Bytes sent on success, -1 on failure or timeout
 */
ssize_t sctp_retry_send(int fd, const void *data, size_t len, uint32_t ppid,
                        int max_wait_ms, const char *label);

#endif /* S1N2_SCTP_TRANSPORT_H */
