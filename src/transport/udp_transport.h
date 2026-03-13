/**
 * @file udp_transport.h
 * @brief UDP transport initialization API
 *
 * Wireshark correspondence:
 *   - UDP port 2152 (GTP-U)
 */
#ifndef S1N2_UDP_TRANSPORT_H
#define S1N2_UDP_TRANSPORT_H

#include "s1n2_converter.h"

/**
 * @brief Initialize S1-U and N3 UDP sockets
 *
 * Creates and binds S1-U (recv from eNB) and N3 (send to/recv from UPF) sockets.
 * Detects local N3 IP for AMF reporting.
 *
 * @param ctx Converter context (s1u_fd, n3_fd, s1u_addr, n3_addr populated)
 * @param s1u_bind_addr S1-U bind address
 * @param s1u_port S1-U port (typically 2152)
 * @param n3_remote_addr UPF N3 address
 * @param n3_remote_port UPF N3 port (typically 2152)
 * @return 0 on success, -1 on error
 */
int udp_transport_init(s1n2_context_t *ctx,
                       const char *s1u_bind_addr, int s1u_port,
                       const char *n3_remote_addr, int n3_remote_port);

#endif /* S1N2_UDP_TRANSPORT_H */
