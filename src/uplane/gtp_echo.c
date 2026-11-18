#include "s1n2_log.h"
/**
 * @file gtp_echo.c
 * @brief GTP-U Echo Request / Echo Response handling
 *
 * Wireshark trace: GTP-U Echo Request (type=1), Echo Response (type=2)
 */
#include <stdio.h>
#include <stdint.h>

#include "gtp_header.h"
#include "gtp_uplane_internal.h"

int s1n2_handle_gtpu_echo(int reply_fd, uint32_t teid, uint8_t msg_type) {
    if (msg_type == 1) {
        /* Echo Request → send Echo Response */
        LOG_DEBUG("GTP-U Echo Request received\n");

        uint8_t echo_response[8];
        s1n2_build_gtpu_header(echo_response, sizeof(echo_response), teid, 2);
        echo_response[2] = 0x00; /* Length = 0 */
        echo_response[3] = 0x00;

        ssize_t sent = send(reply_fd, echo_response, 8, 0);
        if (sent == 8) {
            LOG_INFO("GTP-U Echo Response sent\n");

        } else {
            LOG_ERROR("Failed to send GTP-U Echo Response: %zd\n", sent);

        }
        return 0;
    }

    if (msg_type == 2) {
        /* Echo Response — just log */
        LOG_DEBUG("GTP-U Echo Response received\n");

        return 0;
    }

    return -1; /* not an echo message */
}
