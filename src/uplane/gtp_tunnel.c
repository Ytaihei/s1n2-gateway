#include "gtp_header.h"
#include "s1n2_log.h"
/*
 * GTP-U Tunnel Management for s1n2-gateway Protocol Converter
 * Comprehensive S1-U ↔ N3 GTP-U TEID bidirectional mapping
 *
 * Features:
 * - Bidirectional TEID mapping (S1-U ↔ N3)
 * - Dynamic memory optimization
 * - Enhanced error handling
 * - Connection state management
 * - Performance monitoring
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#include "gtp_tunnel.h"

// Enhanced TEID mapping hash table size
#define TEID_HASH_SIZE 256
#define MAX_TEID_MAPPINGS 1024
#define TEID_TIMEOUT_SECONDS 3600  // 1 hour timeout for unused mappings

// Enhanced TEID mapping structure with additional metadata
typedef struct teid_mapping_enhanced {
    // Basic mapping information
    uint32_t s1u_teid;          // S1-U TEID (from eNB)
    uint32_t n3_teid;           // N3 TEID (to UPF)
    uint32_t s1u_ip;            // S1-U source IP
    uint32_t n3_ip;             // N3 destination IP
    uint16_t s1u_port;          // S1-U source port
    uint16_t n3_port;           // N3 destination port

    // Enhanced metadata
    time_t created_time;        // Mapping creation time
    time_t last_used;           // Last activity timestamp
    uint64_t packet_count_s1u;  // S1-U packet counter
    uint64_t packet_count_n3;   // N3 packet counter
    uint64_t bytes_s1u;         // S1-U bytes transferred
    uint64_t bytes_n3;          // N3 bytes transferred

    // Connection state
    uint8_t state;              // Mapping state (ACTIVE, IDLE, EXPIRED)
    uint8_t pdu_session_id;     // Associated PDU Session ID
    uint8_t qfi;                // QoS Flow Identifier for N3 PDU Session Container
    uint16_t bearer_id;         // Associated Bearer ID (for E-RAB)

    // Hash table linkage
    struct teid_mapping_enhanced *next_s1u;  // Next in S1-U hash chain
    struct teid_mapping_enhanced *next_n3;   // Next in N3 hash chain
    struct teid_mapping_enhanced *prev;      // Previous in LRU chain
    struct teid_mapping_enhanced *next_lru;  // Next in LRU chain
} teid_mapping_enhanced_t;

// Enhanced mapping states
#define TEID_STATE_ACTIVE   0x01
#define TEID_STATE_IDLE     0x02
#define TEID_STATE_EXPIRED  0x03

// Enhanced TEID manager structure
typedef struct {
    // Hash tables for O(1) lookups
    teid_mapping_enhanced_t *s1u_hash_table[TEID_HASH_SIZE];
    teid_mapping_enhanced_t *n3_hash_table[TEID_HASH_SIZE];

    // LRU cache for memory management
    teid_mapping_enhanced_t *lru_head;
    teid_mapping_enhanced_t *lru_tail;

    // Statistics
    uint32_t total_mappings;
    uint32_t active_mappings;
    uint32_t expired_mappings;
    uint32_t next_n3_teid;

    // Performance metrics
    uint64_t lookup_count_s1u;
    uint64_t lookup_count_n3;
    uint64_t cache_hits;
    uint64_t cache_misses;

    // Memory pool
    teid_mapping_enhanced_t *free_mappings;
    teid_mapping_enhanced_t mapping_pool[MAX_TEID_MAPPINGS];

    // Configuration
    time_t cleanup_interval;
    time_t last_cleanup;
} teid_manager_t;

static teid_manager_t g_teid_manager;

// Hash function for TEID values
static inline uint32_t teid_hash(uint32_t teid) {
    // Simple hash function - can be improved with more sophisticated algorithms
    return (teid ^ (teid >> 16)) % TEID_HASH_SIZE;
}

// Initialize the enhanced TEID manager
int gtp_tunnel_init(void) {
    memset(&g_teid_manager, 0, sizeof(teid_manager_t));

    // Initialize hash tables
    for (int i = 0; i < TEID_HASH_SIZE; i++) {
        g_teid_manager.s1u_hash_table[i] = NULL;
        g_teid_manager.n3_hash_table[i] = NULL;
    }

    // Initialize memory pool
    for (int i = 0; i < MAX_TEID_MAPPINGS - 1; i++) {
        g_teid_manager.mapping_pool[i].next_s1u = &g_teid_manager.mapping_pool[i + 1];
    }
    g_teid_manager.mapping_pool[MAX_TEID_MAPPINGS - 1].next_s1u = NULL;
    g_teid_manager.free_mappings = &g_teid_manager.mapping_pool[0];

    // Initialize configuration
    g_teid_manager.next_n3_teid = 0x1000;
    g_teid_manager.cleanup_interval = 300; // 5 minutes
    g_teid_manager.last_cleanup = time(NULL);

    LOG_INFO("Enhanced GTP-U TEID manager initialized (capacity: %d mappings)\n", MAX_TEID_MAPPINGS);
    return 0;
}

// Allocate a mapping from the free pool
static teid_mapping_enhanced_t *allocate_mapping(void) {
    if (!g_teid_manager.free_mappings) {
        LOG_ERROR("TEID mapping pool exhausted\n");
        return NULL;
    }

    teid_mapping_enhanced_t *mapping = g_teid_manager.free_mappings;
    g_teid_manager.free_mappings = mapping->next_s1u;

    memset(mapping, 0, sizeof(teid_mapping_enhanced_t));
    return mapping;
}

// Add mapping to LRU cache (most recently used at head)
static void lru_add_head(teid_mapping_enhanced_t *mapping) {
    mapping->next_lru = g_teid_manager.lru_head;
    mapping->prev = NULL;

    if (g_teid_manager.lru_head) {
        g_teid_manager.lru_head->prev = mapping;
    } else {
        g_teid_manager.lru_tail = mapping;
    }

    g_teid_manager.lru_head = mapping;
}

// Remove mapping from LRU cache
static void lru_remove(teid_mapping_enhanced_t *mapping) {
    if (mapping->prev) {
        mapping->prev->next_lru = mapping->next_lru;
    } else {
        g_teid_manager.lru_head = mapping->next_lru;
    }

    if (mapping->next_lru) {
        mapping->next_lru->prev = mapping->prev;
    } else {
        g_teid_manager.lru_tail = mapping->prev;
    }
}

// Move mapping to head of LRU cache (mark as recently used)
static void lru_touch(teid_mapping_enhanced_t *mapping) {
    if (mapping == g_teid_manager.lru_head) return;

    lru_remove(mapping);
    lru_add_head(mapping);
}

// Enhanced TEID mapping creation with full bidirectional support
int gtp_tunnel_add_mapping(uint32_t s1u_teid, uint32_t s1u_ip, uint16_t s1u_port,
                          uint32_t n3_ip, uint16_t n3_port, uint8_t pdu_session_id, uint16_t bearer_id, uint8_t qfi) {

    // Check if S1-U mapping already exists
    uint32_t s1u_hash_idx = teid_hash(s1u_teid);
    teid_mapping_enhanced_t *existing = g_teid_manager.s1u_hash_table[s1u_hash_idx];

    while (existing) {
        if (existing->s1u_teid == s1u_teid) {
            LOG_DEBUG("S1-U TEID mapping already exists: 0x%08x -> 0x%08x\n",
                   s1u_teid, existing->n3_teid);
            lru_touch(existing);
            existing->last_used = time(NULL);
            return existing->n3_teid;
        }
        existing = existing->next_s1u;
    }

    // Allocate new mapping
    teid_mapping_enhanced_t *mapping = allocate_mapping();
    if (!mapping) {
        LOG_ERROR("Failed to allocate TEID mapping\n");
        return -1;
    }

    // Initialize mapping (default 1:1 mapping for backward compatibility)
    mapping->s1u_teid = s1u_teid;
    mapping->n3_teid = s1u_teid;  // 1:1 mapping

    mapping->s1u_ip = s1u_ip;
    mapping->n3_ip = n3_ip;
    mapping->s1u_port = s1u_port;
    mapping->n3_port = n3_port;
    mapping->pdu_session_id = pdu_session_id;
    mapping->bearer_id = bearer_id;
    mapping->qfi = qfi;
    mapping->state = TEID_STATE_ACTIVE;
    mapping->created_time = time(NULL);
    mapping->last_used = mapping->created_time;

    // Add to S1-U hash table
    mapping->next_s1u = g_teid_manager.s1u_hash_table[s1u_hash_idx];
    g_teid_manager.s1u_hash_table[s1u_hash_idx] = mapping;

    // Add to N3 hash table
    uint32_t n3_hash_idx = teid_hash(mapping->n3_teid);
    mapping->next_n3 = g_teid_manager.n3_hash_table[n3_hash_idx];
    g_teid_manager.n3_hash_table[n3_hash_idx] = mapping;

    // Add to LRU cache
    lru_add_head(mapping);

    // Update statistics
    g_teid_manager.total_mappings++;
    g_teid_manager.active_mappings++;

    LOG_INFO("Added bidirectional TEID mapping: S1-U 0x%08x ↔ N3 0x%08x (PDU Session: %d, Bearer: %d, QFI: %d)\n",
           s1u_teid, mapping->n3_teid, pdu_session_id, bearer_id, qfi);

    return mapping->n3_teid;
}

// Add or update mapping with explicit N3 TEID (Proxy Mode)
// If a mapping with the S1-U TEID already exists, update its N3 TEID and re-index the N3 hash table.
int gtp_tunnel_add_mapping_explicit(uint32_t s1u_teid, uint32_t s1u_ip, uint16_t s1u_port,
                                    uint32_t n3_ip, uint16_t n3_port, uint32_t n3_teid,
                                    uint8_t pdu_session_id, uint16_t bearer_id, uint8_t qfi) {
    // Check if S1-U mapping already exists
    uint32_t s1u_hash_idx = teid_hash(s1u_teid);
    teid_mapping_enhanced_t *existing = g_teid_manager.s1u_hash_table[s1u_hash_idx];

    while (existing) {
        if (existing->s1u_teid == s1u_teid) {
            // Update existing mapping's endpoints and N3 TEID
            uint32_t old_n3_teid = existing->n3_teid;

            // If N3 TEID changes, update N3 hash table linkage
            if (old_n3_teid != n3_teid) {
                uint32_t old_n3_hash = teid_hash(old_n3_teid);
                teid_mapping_enhanced_t **cur = &g_teid_manager.n3_hash_table[old_n3_hash];
                while (*cur) {
                    if (*cur == existing) {
                        *cur = (*cur)->next_n3;
                        break;
                    }
                    cur = &(*cur)->next_n3;
                }

                existing->n3_teid = n3_teid;
                uint32_t new_n3_hash = teid_hash(n3_teid);
                existing->next_n3 = g_teid_manager.n3_hash_table[new_n3_hash];
                g_teid_manager.n3_hash_table[new_n3_hash] = existing;
            }

            existing->s1u_ip = s1u_ip;
            existing->n3_ip = n3_ip;
            existing->s1u_port = s1u_port;
            existing->n3_port = n3_port;
            existing->pdu_session_id = pdu_session_id;
            existing->bearer_id = bearer_id;
            existing->qfi = qfi;
            existing->last_used = time(NULL);
            lru_touch(existing);

            LOG_INFO("Updated TEID mapping (explicit): S1-U 0x%08x ↔ N3 0x%08x (QFI=%u)\n",
                   s1u_teid, n3_teid, qfi);
            return (int)n3_teid;
        }
        existing = existing->next_s1u;
    }

    // Allocate new mapping
    teid_mapping_enhanced_t *mapping = allocate_mapping();
    if (!mapping) {
        LOG_ERROR("Failed to allocate TEID mapping (explicit)\n");
        return -1;
    }

    // Initialize mapping with explicit N3 TEID
    mapping->s1u_teid = s1u_teid;
    mapping->n3_teid = n3_teid;
    mapping->s1u_ip = s1u_ip;
    mapping->n3_ip = n3_ip;
    mapping->s1u_port = s1u_port;
    mapping->n3_port = n3_port;
    mapping->pdu_session_id = pdu_session_id;
    mapping->bearer_id = bearer_id;
    mapping->qfi = qfi;
    mapping->state = TEID_STATE_ACTIVE;
    mapping->created_time = time(NULL);
    mapping->last_used = mapping->created_time;

    // Add to S1-U hash table
    mapping->next_s1u = g_teid_manager.s1u_hash_table[s1u_hash_idx];
    g_teid_manager.s1u_hash_table[s1u_hash_idx] = mapping;

    // Add to N3 hash table
    uint32_t n3_hash_idx = teid_hash(mapping->n3_teid);
    mapping->next_n3 = g_teid_manager.n3_hash_table[n3_hash_idx];
    g_teid_manager.n3_hash_table[n3_hash_idx] = mapping;

    // Add to LRU cache
    lru_add_head(mapping);

    // Update statistics
    g_teid_manager.total_mappings++;
    g_teid_manager.active_mappings++;

    LOG_INFO("Added explicit TEID mapping: S1-U 0x%08x ↔ N3 0x%08x (PDU Session: %d, Bearer: %d, QFI: %u)\n",
           s1u_teid, mapping->n3_teid, pdu_session_id, bearer_id, qfi);

    return (int)mapping->n3_teid;
}

// Enhanced S1-U → N3 TEID lookup with statistics
int gtp_tunnel_lookup_s1u_to_n3(uint32_t s1u_teid, uint32_t *n3_teid, uint32_t *n3_ip, uint16_t *n3_port, uint8_t *qfi) {
    g_teid_manager.lookup_count_s1u++;

    uint32_t hash_idx = teid_hash(s1u_teid);
    teid_mapping_enhanced_t *mapping = g_teid_manager.s1u_hash_table[hash_idx];

    while (mapping) {
        if (mapping->s1u_teid == s1u_teid && mapping->state == TEID_STATE_ACTIVE) {
            // Found mapping - update statistics and LRU
            mapping->last_used = time(NULL);
            mapping->packet_count_s1u++;
            lru_touch(mapping);
            g_teid_manager.cache_hits++;

            // Return mapping information
            if (n3_teid) *n3_teid = mapping->n3_teid;
            if (n3_ip) *n3_ip = mapping->n3_ip;
            if (n3_port) *n3_port = mapping->n3_port;
            if (qfi) *qfi = mapping->qfi;

            LOG_DEBUG("S1-U→N3 lookup: 0x%08x -> 0x%08x QFI=%u (hits: %lu)\n",
                   s1u_teid, mapping->n3_teid, mapping->qfi, mapping->packet_count_s1u);
            return 0;
        }
        mapping = mapping->next_s1u;
    }

    g_teid_manager.cache_misses++;
    LOG_DEBUG("S1-U→N3 lookup failed: TEID 0x%08x not found\n", s1u_teid);
    return -1;
}

// Update QFI for an existing S1-U TEID mapping (called when QFI is extracted after mapping creation)
int gtp_tunnel_update_mapping_qfi(uint32_t s1u_teid, uint8_t qfi) {
    uint32_t hash_idx = teid_hash(s1u_teid);
    teid_mapping_enhanced_t *mapping = g_teid_manager.s1u_hash_table[hash_idx];

    while (mapping) {
        if (mapping->s1u_teid == s1u_teid && mapping->state == TEID_STATE_ACTIVE) {
            uint8_t old_qfi = mapping->qfi;
            mapping->qfi = qfi;
            LOG_INFO("Updated QFI for S1-U TEID 0x%08x: QFI %u -> %u\n",
                   s1u_teid, old_qfi, qfi);
            return 0;
        }
        mapping = mapping->next_s1u;
    }

    LOG_WARN("Cannot update QFI: S1-U TEID 0x%08x not found\n", s1u_teid);
    return -1;
}

// Update byte statistics for a mapping
int gtp_tunnel_update_stats(uint32_t teid, bool is_s1u_direction, uint32_t bytes) {
    uint32_t hash_idx = teid_hash(teid);
    teid_mapping_enhanced_t *mapping;

    if (is_s1u_direction) {
        mapping = g_teid_manager.s1u_hash_table[hash_idx];
        while (mapping && mapping->s1u_teid != teid) {
            mapping = mapping->next_s1u;
        }
    } else {
        mapping = g_teid_manager.n3_hash_table[hash_idx];
        while (mapping && mapping->n3_teid != teid) {
            mapping = mapping->next_n3;
        }
    }

    if (mapping && mapping->state == TEID_STATE_ACTIVE) {
        if (is_s1u_direction) {
            mapping->bytes_s1u += bytes;
        } else {
            mapping->bytes_n3 += bytes;
        }
        mapping->last_used = time(NULL);
        lru_touch(mapping);
        return 0;
    }

    return -1;
}

// Get comprehensive TEID manager statistics
void gtp_tunnel_get_stats(void) {
    time_t current_time = time(NULL);

    LOG_INFO("\n=== Enhanced GTP-U TEID Manager Statistics ===\n");
    LOG_INFO("Total mappings created: %u\n", g_teid_manager.total_mappings);
    LOG_INFO("Active mappings: %u\n", g_teid_manager.active_mappings);
    LOG_INFO("Expired mappings: %u\n", g_teid_manager.expired_mappings);
    LOG_INFO("Next N3 TEID: 0x%08x\n", g_teid_manager.next_n3_teid);
    LOG_INFO("\nLookup Statistics:\n");
    LOG_INFO("S1-U lookups: %lu\n", g_teid_manager.lookup_count_s1u);
    LOG_INFO("N3 lookups: %lu\n", g_teid_manager.lookup_count_n3);
    LOG_INFO("Cache hits: %lu\n", g_teid_manager.cache_hits);
    LOG_INFO("Cache misses: %lu\n", g_teid_manager.cache_misses);

    if (g_teid_manager.lookup_count_s1u + g_teid_manager.lookup_count_n3 > 0) {
        double hit_rate = (double)g_teid_manager.cache_hits /
                         (g_teid_manager.cache_hits + g_teid_manager.cache_misses) * 100.0;
        LOG_INFO("Cache hit rate: %.2f%%\n", hit_rate);
    }

    LOG_INFO("Last cleanup: %ld seconds ago\n", current_time - g_teid_manager.last_cleanup);
    LOG_INFO("Memory pool utilization: %u/%d (%.1f%%)\n",
           g_teid_manager.total_mappings, MAX_TEID_MAPPINGS,
           (double)g_teid_manager.total_mappings / MAX_TEID_MAPPINGS * 100.0);

}

// Enhanced GTP-U packet processing with bidirectional TEID conversion
int gtp_tunnel_process_s1u_to_n3(uint8_t *packet, size_t packet_len, uint8_t **output_packet, size_t *output_len) {
    if (!packet || packet_len < 8 || !output_packet || !output_len) {
        return -1;
    }

    // Extract S1-U TEID from GTP-U header (offset 4-7)
    uint32_t s1u_teid;
    memcpy(&s1u_teid, packet + 4, sizeof(s1u_teid));
    s1u_teid = ntohl(s1u_teid);

    // Lookup N3 mapping
    uint32_t n3_teid, n3_ip;
    uint16_t n3_port;

    uint8_t qfi = 0;
    if (gtp_tunnel_lookup_s1u_to_n3(s1u_teid, &n3_teid, &n3_ip, &n3_port, &qfi) != 0) {
        LOG_WARN("S1-U to N3 TEID mapping not found: 0x%08x\n", s1u_teid);
        return -1;
    }

    // ================================================================
    // Convert S1-U GTP-U → N3 GTP-U (add PDU Session Container header)
    // ================================================================
    //
    // S1-U format (flags=0x30): [8-byte GTP-U header][T-PDU payload]
    // N3  format (flags=0x34): [8-byte GTP-U header][seq(2)+npdu(1)+next_ext_type(1)]
    //                          [PDU Session Container ext hdr (4 bytes)][T-PDU payload]
    //
    // PDU Session Container (UL, type=1):
    //   Extension Header Type = 0x85
    //   Length = 0x01 (4 bytes)
    //   Octet 1: PDU Type (0001) | spare (0000) = 0x10
    //   Octet 2: QFI (6 bits) | spare (2 bits)
    //   Next Extension Header Type = 0x00
    // ================================================================

    uint8_t flags = packet[0];
    size_t orig_hdr_len;
    if (s1n2_gtpu_payload_offset(packet, packet_len, &orig_hdr_len) != 0 ||
        packet[1] != 0xff || packet_len - orig_hdr_len > UINT16_MAX - 8) return -1;

    // Output: new header (12 bytes) + PDU Session Container (4 bytes) + original T-PDU payload
    size_t payload_len = packet_len - orig_hdr_len;
    size_t new_packet_len = 12 + 4 + payload_len;  // 12 = base hdr + optional, 4 = ext hdr

    *output_packet = malloc(new_packet_len);
    if (!*output_packet) {
        return -1;
    }

    uint8_t *out = *output_packet;

    // Copy version/type from original, set E flag
    out[0] = (flags & 0xF8) | 0x04;  // Keep version/PT/reserved, set E=1, clear S/PN
    out[1] = packet[1];               // Message Type (0xFF = G-PDU)

    // Length = payload + 4 (optional fields seq/npdu/next_ext) + 4 (extension header)
    uint16_t new_gtp_length = (uint16_t)(payload_len + 8);
    uint16_t length_be = htons(new_gtp_length);
    memcpy(out + 2, &length_be, sizeof(length_be));

    // N3 TEID
    uint32_t teid_be = htonl(n3_teid);
    memcpy(out + 4, &teid_be, sizeof(teid_be));

    // Optional fields (when E flag is set)
    out[8]  = 0x00;  // Sequence Number MSB
    out[9]  = 0x00;  // Sequence Number LSB
    out[10] = 0x00;  // N-PDU Number
    out[11] = 0x85;  // Next Extension Header Type = PDU Session Container

    // PDU Session Container extension header (UL, type=1)
    // 3GPP TS 38.415 Section 5.5.2.1:
    //   Octet 1: PDU Type(4 bits, MSB) | Spare(4 bits, LSB) → 0x10 for UL
    //   Octet 2: Spare(1) | Spare(1) | QFI(6 bits, LSB)    → QFI in bits 5-0
    out[12] = 0x01;                   // Length: 1 (= 4 bytes)
    out[13] = 0x10;                   // PDU Type=1 (UL) | spare
    out[14] = (qfi & 0x3F);          // QFI in bits 5-0 (no shift)
    out[15] = 0x00;                   // Next Extension Header Type = none

    // Copy T-PDU payload
    if (payload_len > 0) {
        memcpy(out + 16, packet + orig_hdr_len, payload_len);
    }

    *output_len = new_packet_len;

    // Update statistics
    gtp_tunnel_update_stats(s1u_teid, true, new_packet_len);

    LOG_DEBUG("S1-U→N3 GTP-U conversion: TEID 0x%08x -> 0x%08x QFI=%u (%zu→%zu bytes)\n",
           s1u_teid, n3_teid, qfi, packet_len, new_packet_len);

    return 0;
}

int gtp_tunnel_process_n3_to_s1u(uint8_t *packet, size_t packet_len, uint8_t **output_packet, size_t *output_len) {
    if (!packet || packet_len < 8 || !output_packet || !output_len) {
        return -1;
    }

    // ============================================================================
    // TRANSPARENT PROXY MODE for Downlink (N3 → S1-U)
    // ============================================================================
    // Option A: Pure Transparent Proxy (following Open5GS standard pattern)
    //
    // Architecture:
    //   - s1n2 reports eNB's downlink TEID to AMF (e.g., 0x01000708)
    //   - AMF → SMF → UPF: Same TEID propagated
    //   - UPF sends downlink packets with TEID = eNB's downlink TEID
    //   - s1n2 forwards packets WITHOUT TEID translation
    //   - eNB receives with its own TEID
    //
    // This matches Open5GS MME/SMF behavior:
    //   - MME: passes eNB S1-U TEID directly to SGW-C
    //   - SMF: passes gNB N3 TEID directly to UPF
    //
    // Note: Uplink (S1-U → N3) still requires TEID translation because
    //       s1n2 allocates its own S1-U uplink TEID (0x00000001) which
    //       must be converted to UPF's N3 TEID.
    //
    // Result: s1n2 operates as "Hybrid Proxy"
    //   - Uplink:   TEID translation (0x00000001 → UPF TEID)
    //   - Downlink: Transparent proxy (eNB TEID → eNB TEID, no translation)
    // ============================================================================

    // Extract N3 TEID for logging
    uint32_t n3_teid;
    size_t payload_offset;
    if (s1n2_gtpu_payload_offset(packet, packet_len, &payload_offset) != 0 || packet[1] != 0xff) return -1;
    memcpy(&n3_teid, packet + 4, sizeof(n3_teid));
    n3_teid = ntohl(n3_teid);

    // Forward packet as-is without TEID translation
    *output_packet = malloc(packet_len);
    if (!*output_packet) {
        LOG_ERROR("Memory allocation failed for downlink transparent proxy\n");
        return -1;
    }

    memcpy(*output_packet, packet, packet_len);
    *output_len = packet_len;

    // Update statistics (using received TEID)
    gtp_tunnel_update_stats(n3_teid, false, packet_len);

    LOG_INFO("Downlink N3→S1-U: Transparent proxy (no TEID translation), TEID 0x%08x (%zu bytes)\n",
           n3_teid, packet_len);

    return 0;
}

// Periodic maintenance function (should be called regularly)
void gtp_tunnel_maintenance(void) {
    // Print stats periodically
    static time_t last_stats = 0;
    time_t current_time = time(NULL);

    if (current_time - last_stats >= 300) { // Every 5 minutes
        gtp_tunnel_get_stats();
        last_stats = current_time;
    }
}

// Complete cleanup - free all resources
void gtp_tunnel_cleanup(void) {
    int i;
    teid_mapping_enhanced_t *mapping, *temp;

    LOG_INFO("[GTP-U] Starting complete cleanup...\n");

    // Clear all hash table entries
    for (i = 0; i < TEID_HASH_SIZE; i++) {
        mapping = g_teid_manager.s1u_hash_table[i];
        while (mapping != NULL) {
            temp = mapping->next_s1u;
            // Note: Don't free() since mappings come from static pool
            mapping = temp;
        }
        g_teid_manager.s1u_hash_table[i] = NULL;
        g_teid_manager.n3_hash_table[i] = NULL;
    }

    // Clear LRU cache
    g_teid_manager.lru_head = NULL;
    g_teid_manager.lru_tail = NULL;

    // Reset counters and statistics
    g_teid_manager.total_mappings = 0;
    g_teid_manager.active_mappings = 0;
    g_teid_manager.expired_mappings = 0;
    g_teid_manager.lookup_count_s1u = 0;
    g_teid_manager.lookup_count_n3 = 0;
    g_teid_manager.cache_hits = 0;
    g_teid_manager.cache_misses = 0;

    // Reset free pool
    for (int j = 0; j < MAX_TEID_MAPPINGS - 1; j++) {
        g_teid_manager.mapping_pool[j].next_s1u = &g_teid_manager.mapping_pool[j + 1];
    }
    g_teid_manager.mapping_pool[MAX_TEID_MAPPINGS - 1].next_s1u = NULL;
    g_teid_manager.free_mappings = &g_teid_manager.mapping_pool[0];

    LOG_INFO("[GTP-U] Complete cleanup finished - all resources reset\n");
}
