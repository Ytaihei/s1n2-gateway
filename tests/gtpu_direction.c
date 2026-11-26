/* All traffic stays on loopback; run in an isolated container. */
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "gtp_header.h"
#include "gtp_tunnel.h"

static void expect_empty(int fd) {
    uint8_t byte;
    assert(recv(fd, &byte, 1, MSG_DONTWAIT) == -1);
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
}

int main(void) {
    s1n2_context_t *ctx = calloc(1, sizeof(*ctx));
    assert(ctx);
    int n3[2], s1[2];
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, n3) == 0);
    assert(socketpair(AF_UNIX, SOCK_DGRAM, 0, s1) == 0);
    ctx->n3_fd = n3[0];
    ctx->s1u_fd = socket(AF_INET, SOCK_DGRAM, 0);
    int enb = socket(AF_INET, SOCK_DGRAM, 0);
    assert(ctx->s1u_fd >= 0 && enb >= 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(2152),
                               .sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(bind(enb, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    ctx->num_ue_mappings = 1;
    ue_id_mapping_t *ue = &ctx->ue_mappings[0];
    ue->in_use = ue->has_s1n2_uplink_teid = ue->has_enb_s1u_info = true;
    ue->s1n2_s1u_uplink_teid = ue->enb_s1u_teid = 1;
    ue->enb_s1u_ip = addr.sin_addr.s_addr;
    assert(gtp_tunnel_init() == 0);
    assert(gtp_tunnel_add_mapping_explicit(1, addr.sin_addr.s_addr, 2152,
        addr.sin_addr.s_addr, 2152, 0x500, 1, 5, 9) == 0x500);

    uint8_t up[] = {0x30,0xff,0,4,0,0,0,1,0x45,0,0,4};
    uint8_t down[] = {0x34,0xff,0,12,0,0,0,1,0,0,0,0x85,1,0,9,0,0x45,0,0,4};
    uint8_t received[64];
    assert(s1n2_handle_gtpu_message(ctx, up, sizeof(up), S1N2_GTPU_FROM_S1U) == 0);
    assert(recv(n3[1], received, sizeof(received), MSG_DONTWAIT) == 20);
    const uint8_t expected[] = {0x34,0xff,0,12,0,0,5,0,0,0,0,0x85,1,0x10,9,0,0x45,0,0,4};
    assert(memcmp(received, expected, sizeof(expected)) == 0);
    expect_empty(enb);
    assert(s1n2_handle_gtpu_message(ctx, down, sizeof(down), S1N2_GTPU_FROM_N3) == 0);
    assert(recv(enb, received, sizeof(received), MSG_DONTWAIT) == sizeof(down));
    assert(memcmp(received, down, sizeof(down)) == 0);
    expect_empty(n3[1]);

    /* A TEID belonging only to the opposite direction must be rejected. */
    ue->enb_s1u_teid = 2;
    assert(s1n2_handle_gtpu_message(ctx, down, sizeof(down), S1N2_GTPU_FROM_N3) == -1);
    up[7] = 2;
    assert(s1n2_handle_gtpu_message(ctx, up, sizeof(up), S1N2_GTPU_FROM_S1U) == -1);
    up[7] = 99;
    assert(s1n2_handle_gtpu_message(ctx, up, sizeof(up), S1N2_GTPU_FROM_N3) == -1);
    assert(s1n2_handle_gtpu_message(ctx, up, 7, S1N2_GTPU_FROM_S1U) == -1);
    assert(s1n2_handle_gtpu_message(ctx, up, sizeof(up), (s1n2_gtpu_ingress_t)99) == -1);
    expect_empty(n3[1]); expect_empty(enb);

    /* Echo responses use the ingress socket too. */
    close(ctx->s1u_fd); ctx->s1u_fd = s1[0];
    uint8_t echo[] = {0x30,1,0,0,0,0,0,0};
    assert(s1n2_handle_gtpu_message(ctx, echo, sizeof(echo), S1N2_GTPU_FROM_S1U) == 0);
    assert(recv(s1[1], received, sizeof(received), MSG_DONTWAIT) == 8);
    assert(received[1] == 2); expect_empty(n3[1]);
    assert(s1n2_handle_gtpu_message(ctx, echo, sizeof(echo), S1N2_GTPU_FROM_N3) == 0);
    assert(recv(n3[1], received, sizeof(received), MSG_DONTWAIT) == 8);
    assert(received[1] == 2); expect_empty(s1[1]);
    close(enb); close(n3[0]); close(n3[1]); close(s1[0]); close(s1[1]);
    free(ctx);
    puts("PASS: GTP-U direction, colliding TEIDs, rejection and echo routing");
    return 0;
}
