#ifndef S1N2_GTP_H
#define S1N2_GTP_H

#include <stddef.h>
#include <stdint.h>

#include "s1n2_converter.h"

int s1n2_add_teid_mapping(s1n2_context_t *ctx, uint32_t s1u_teid, uint32_t s1u_ip, uint16_t s1u_port);
int s1n2_find_teid_mapping_by_n3(s1n2_context_t *ctx, uint32_t n3_teid, teid_mapping_t **mapping);
int s1n2_remove_teid_mapping(s1n2_context_t *ctx, uint32_t s1u_teid);

int s1n2_parse_gtpu_header(uint8_t *data, size_t len, uint32_t *teid, uint8_t *message_type);
int s1n2_build_gtpu_header(uint8_t *data, size_t len, uint32_t teid, uint8_t message_type);
int s1n2_handle_gtpu_message(s1n2_context_t *ctx, uint8_t *data, size_t len);

#endif // S1N2_GTP_H
