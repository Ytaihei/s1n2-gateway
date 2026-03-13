#ifndef GTP_TUNNEL_H
#define GTP_TUNNEL_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

int gtp_tunnel_init(void);
int gtp_tunnel_add_mapping(uint32_t s1u_teid, uint32_t s1u_ip, uint16_t s1u_port,
                          uint32_t n3_ip, uint16_t n3_port,
                          uint8_t pdu_session_id, uint16_t bearer_id, uint8_t qfi);
// Explicitly set both S1-U TEID and N3 TEID for bidirectional mapping (Proxy Mode support)
int gtp_tunnel_add_mapping_explicit(uint32_t s1u_teid, uint32_t s1u_ip, uint16_t s1u_port,
                                    uint32_t n3_ip, uint16_t n3_port, uint32_t n3_teid,
                                    uint8_t pdu_session_id, uint16_t bearer_id, uint8_t qfi);
int gtp_tunnel_lookup_s1u_to_n3(uint32_t s1u_teid, uint32_t *n3_teid,
                               uint32_t *n3_ip, uint16_t *n3_port, uint8_t *qfi);
int gtp_tunnel_lookup_n3_to_s1u(uint32_t n3_teid, uint32_t *s1u_teid,
                               uint32_t *s1u_ip, uint16_t *s1u_port);
int gtp_tunnel_remove_mapping(uint32_t s1u_teid);
int gtp_tunnel_cleanup_expired(void);
int gtp_tunnel_update_stats(uint32_t teid, bool is_s1u_direction, uint32_t bytes);
int gtp_tunnel_update_mapping_qfi(uint32_t s1u_teid, uint8_t qfi);
void gtp_tunnel_get_stats(void);
int gtp_tunnel_process_s1u_to_n3(uint8_t *packet, size_t packet_len,
                                uint8_t **output_packet, size_t *output_len);
int gtp_tunnel_process_n3_to_s1u(uint8_t *packet, size_t packet_len,
                                uint8_t **output_packet, size_t *output_len);
void gtp_tunnel_maintenance(void);

#ifdef __cplusplus
}
#endif

#endif /* GTP_TUNNEL_H */
