/**
 * @file event_loop.h
 * @brief Event loop API
 *
 * Wireshark correspondence:
 *   - S1AP / NGAP / GTP-U message routing from poll() events
 */
#ifndef S1N2_EVENT_LOOP_H
#define S1N2_EVENT_LOOP_H

#include "s1n2_converter.h"

/**
 * @brief Run the main poll() event loop
 *
 * Multiplexes S1C (SCTP server), N2 (SCTP client), S1U (UDP), N3 (UDP)
 * and dispatches received messages to the appropriate handlers.
 *
 * @param ctx Converter context (all fd/addr fields must be populated)
 * @param n2_remote_addr AMF address for retry logging
 * @param n2_remote_port AMF port for retry logging
 */
void event_loop_run(s1n2_context_t *ctx, const char *n2_remote_addr, int n2_remote_port);

#endif /* S1N2_EVENT_LOOP_H */
