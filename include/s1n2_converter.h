#ifndef S1N2_CONVERTER_H
#define S1N2_CONVERTER_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "subscriber_auth.h"

#define S1N2_MAX_UE_MAPPINGS 64
#define S1N2_MAX_UE_SECURITY_CAP_LEN 128

typedef struct {
    bool has_security_mode;
    bool has_selected_alg_5g;
    uint8_t selected_alg_5g;
    uint8_t selected_alg_4g;
    uint8_t ngksi;
    uint8_t ngksi_octet;
    uint8_t ue_security_cap[S1N2_MAX_UE_SECURITY_CAP_LEN];
    uint8_t ue_security_cap_len;
    bool has_ue_security_cap;
    uint8_t ue_security_cap_5g[S1N2_MAX_UE_SECURITY_CAP_LEN];
    uint8_t ue_security_cap_5g_len;
    bool has_ue_security_cap_5g;
    bool imeisv_requested;
    bool additional_security_info_present;
    uint8_t additional_security_info;
} s1n2_security_mode_info_t;

// E-RAB Setup Information structure for 4G to 5G conversion
typedef struct {
    // Original 4G parameters
    uint8_t e_rab_id;            // E-RAB ID (1-15)
    uint8_t qos_arp_priority;    // ARP priority level
    uint8_t qos_arp_preemption_capability;  // Pre-emption capability
    uint8_t qos_arp_preemption_vulnerability; // Pre-emption vulnerability
    uint32_t qos_gbr_dl;         // GBR Downlink (bytes/sec)
    uint32_t qos_gbr_ul;         // GBR Uplink (bytes/sec)
    uint32_t qos_mbr_dl;         // MBR Downlink (bytes/sec)
    uint32_t qos_mbr_ul;         // MBR Uplink (bytes/sec)
    uint32_t ul_gtp_teid;        // SGW-U側GTP-U TEID (uplink)
    uint32_t ul_transport_address; // SGW IP address
    uint16_t ul_transport_port;   // SGW GTP-U port

    // Mapped 5G parameters
    uint8_t pdu_session_id;      // Mapped PDU Session ID
    uint32_t dl_gtp_teid;        // UPF側GTP-U TEID (downlink)
    uint32_t dl_transport_address; // UPF IP address
    uint16_t dl_transport_port;   // UPF GTP-U port

    // UPF N3 downlink tunnel info (for reverse mapping)
    uint32_t upf_n3_ip;          // UPF N3 IP address (network byte order)
    uint32_t upf_n3_teid;        // UPF N3 downlink TEID (host byte order)

    bool is_active;              // Mapping active flag
    time_t created_time;         // Creation timestamp

    // 4G→5G NAS Conversion flags (from diary.md procedure analysis)
    bool nas_converted;          // NAS conversion completed flag
} e_rab_setup_info_t;

// Message structure
typedef struct {
    uint8_t *data;
    size_t len;
    uint8_t procedure_code;
    uint8_t criticality;
    bool is_s1ap;
} s1n2_message_t;

// Deferred S1SetupRequest queue entry
typedef struct {
    uint8_t s1ap_data[1024];
    size_t s1ap_len;
    time_t received_time;
} deferred_s1setup_t;

// GTP-U TEID mapping structure
typedef struct s1n2_teid_mapping {
    uint32_t s1u_teid;  // S1-U TEID (from eNB)
    uint32_t n3_teid;   // N3 TEID (to UPF)
    uint32_t s1u_ip;    // S1-U source IP
    uint32_t n3_ip;     // N3 destination IP
    uint16_t s1u_port;  // S1-U source port
    uint16_t n3_port;   // N3 destination port
    time_t last_used;   // Last activity timestamp
} teid_mapping_t;

typedef struct ue_id_mapping {
    bool in_use;
    long enb_ue_s1ap_id;
    long mme_ue_s1ap_id;
    long ran_ue_ngap_id;
    long amf_ue_ngap_id;
    time_t created_time;
    time_t last_update;

    // Authentication context
    char imsi[16];              // IMSI extracted from Registration Request
    uint8_t rand[16];           // RAND from Authentication Request
    bool rand_cached;           // RAND has been cached
    time_t rand_timestamp;      // When RAND was cached
    uint8_t autn[16];           // AUTN from Authentication Request
    uint8_t sqn_xor_ak[6];      // SQN xor AK extracted from AUTN
    bool autn_cached;           // AUTN/SQN^AK has been cached

    // Security mode context (5G→4G mapping)
    bool has_selected_alg_5g;        // Cached 5G NAS security algorithms octet
    uint8_t selected_alg_5g;
    uint8_t selected_nas_security_alg; // Selected NAS security algorithms (4G encoding)
    uint8_t last_ngksi;                // Latest NAS key set identifier (lower 3 bits used)
    uint8_t last_ngksi_octet;          // Full ngKSI octet including TSC bit
    bool has_security_mode;            // Cached security mode information valid flag
    uint8_t cached_ue_security_cap[S1N2_MAX_UE_SECURITY_CAP_LEN]; // Cached UE security capability
    uint8_t cached_ue_security_cap_len;
    bool has_cached_ue_security_cap;
    uint8_t cached_ue_security_cap_5g[S1N2_MAX_UE_SECURITY_CAP_LEN];
    uint8_t cached_ue_security_cap_5g_len;
    bool has_cached_ue_security_cap_5g;
    bool imeisv_requested;             // Whether IMEISV was requested in SMC
    bool additional_security_info_present;
    uint8_t additional_security_info;

    // 4G UE Network Capability from Initial Attach (for Security Mode Command)
    uint8_t ue_network_cap_4g[S1N2_MAX_UE_SECURITY_CAP_LEN];  // Original 4G UE network capability
    uint8_t ue_network_cap_4g_len;                            // Length of 4G UE network capability
    bool has_ue_network_cap_4g;                               // Whether 4G capability is cached

    // 4G NAS security keys (for MAC/encryption computation)
    uint8_t k_nas_int[16];             // K_NASint - NAS integrity protection key (4G)
    uint8_t k_nas_enc[16];             // K_NASenc - NAS encryption key (4G)
    bool has_nas_keys;                 // Whether NAS keys are available
    uint32_t nas_ul_count;             // Uplink NAS COUNT (4G)
    uint32_t nas_dl_count;             // Downlink NAS COUNT (4G)

    // 4G EPS key hierarchy (3GPP TS 33.401)
    uint8_t kasme[32];                 // KASME - EPS master key (256 bits)
    bool has_kasme;                    // Whether KASME has been derived
    uint8_t kenb[32];                  // KeNB - eNB key (256 bits)
    bool has_kenb;                     // Whether KeNB has been derived
    uint32_t kenb_ul_count;            // NAS ul_count used for KeNB derivation

    // 5G NAS security keys and context (3GPP TS 33.501)
    uint8_t kausf[32];                 // Kausf - derived from CK||IK (256 bits)
    uint8_t kseaf[32];                 // Kseaf - derived from Kausf (256 bits)
    uint8_t kamf[32];                  // Kamf - derived from Kseaf (256 bits)
    uint8_t k_nas_int_5g[16];          // K_NASint - 5G NAS integrity key (128 bits)
    uint8_t k_nas_enc_5g[16];          // K_NASenc - 5G NAS encryption key (128 bits)
    bool has_5g_nas_keys;              // Whether 5G NAS keys have been derived
    uint8_t abba[2];                   // ABBA parameter from Authentication Request
    uint8_t abba_len;                  // Length of ABBA (typically 2)

    // 5G NAS security context
    uint32_t nas_ul_count_5g;          // Uplink NAS COUNT (5G) - for MAC calculation
    uint32_t nas_dl_count_5g;          // Last authenticated downlink COUNT (24 bits)
    bool has_nas_dl_count_5g;
    bool has_sent_smc;                 // Security Mode Complete sent flag

    // Registration Request caching (for piggybacked re-transmission after Security Mode Complete)
    uint8_t cached_registration_request[512];  // Cached 5G Registration Request from InitialUEMessage
    int cached_reg_req_len;                    // Length of cached Registration Request

    // InitialContextSetup tracking (prevent duplicate ICS sending)
    bool ics_sent;                             // InitialContextSetupRequest has been sent
    time_t ics_sent_time;                      // When ICS was sent
    uint8_t ics_e_rab_id;                      // E-RAB ID used in last ICS
    // InitialContextSetup state tracking (response/attempts)
    bool ics_completed;                        // InitialContextSetup completed successfully
    bool ics_failed;                           // Last InitialContextSetup attempt failed
    int ics_attempts;                          // Number of InitialContextSetup attempts

    // Coordination with AMF InitialContextSetupRequest and deferred NGAP ICS Response
    bool amf_ics_requested;                    // AMF has sent InitialContextSetupRequest
    bool has_pending_ngap_ics;                 // NGAP InitialContextSetupResponse is built and queued
    uint8_t pending_ngap_ics[512];             // Queued NGAP InitialContextSetupResponse payload
    size_t pending_ngap_ics_len;               // Length of queued NGAP ICS Response

    // S1AP data caching for deferred NGAP conversion (after QFI extraction)
    bool has_pending_s1ap_ics;                 // S1AP InitialContextSetupResponse raw data is cached
    uint8_t pending_s1ap_ics[512];             // Cached S1AP InitialContextSetupResponse payload
    size_t pending_s1ap_ics_len;               // Length of cached S1AP ICS Response

    // ESM message container caching (for Attach Accept piggybacking)
    uint8_t cached_esm_pdn_request[64];        // UE's PDN connectivity request from Attach Request
    uint8_t cached_esm_pdn_request_len;        // Length of cached PDN request
    bool has_cached_esm_pdn_request;           // Whether PDN connectivity request is cached

    // PDU Session establishment context (for automatic PDU Session Establishment Request)
    bool has_pending_pdu_session;              // E-RAB info cached, ready for PDU Session establishment
    uint8_t pdu_session_id;                    // PDU Session ID (mapped from E-RAB ID)
    uint8_t qci;                               // QCI from E-RAB setup
    uint8_t qfi;                               // Mapped 5QI/QFI for 5G
    char apn[64];                              // APN/DNN name
    uint8_t pdu_ipv4[4];
    bool has_pdu_ipv4;
    uint8_t pending_registration_accept[512];
    size_t pending_registration_accept_len;
    bool registration_complete_sent;
    bool pdu_session_requested;
    bool send_pdu_session_establishment;       // Flag to send PDU Session Establishment Request after Reg Complete

    // User Location Information (cached from S1AP/NGAP messages for NGAP UplinkNASTransport)
    uint8_t plmn_id[3];                        // PLMN Identity (MCC+MNC)
    uint8_t plmn_id_len;                       // PLMN Identity length (typically 3)
    uint32_t cell_id;                          // Cell ID (28-bit for 4G EUTRAN-CGI, 36-bit for 5G NR-CGI)
    uint16_t tac;                              // Tracking Area Code
    bool has_location_info;                    // Whether location information is cached
    bool has_tau_request_tai;                  // TAU Request provided last visited TAI
    uint8_t tau_request_tai_plmn[3];           // PLMN from TAU Request (PLMN identity format)
    uint16_t tau_request_tac;                  // TAC from TAU Request
    bool has_tau_request_lai;                  // TAU Request provided LAI
    uint8_t tau_request_lai_plmn[3];           // LAI PLMN from TAU Request
    uint16_t tau_request_lac;                  // LAI LAC from TAU Request

    // UPF N3 downlink tunnel info (for reverse TEID mapping in downlink GTP-U)
    uint32_t upf_n3_ip;                        // UPF N3 IP address (network byte order)
    uint32_t upf_n3_teid;                      // UPF N3 downlink TEID (host byte order)
    bool has_upf_n3_info;                      // Whether UPF N3 tunnel info is available

    // eNB S1-U tunnel info (for reverse TEID mapping in downlink GTP-U)
    uint32_t enb_s1u_ip;                       // eNB S1-U IP address (network byte order)
    uint32_t enb_s1u_teid;                     // eNB S1-U uplink TEID (host byte order)
    bool has_enb_s1u_info;                     // Whether eNB S1-U tunnel info is available

    // s1n2 S1-U uplink tunnel info (for uplink TEID mapping: S1-U -> N3)
    uint32_t s1n2_s1u_uplink_teid;             // s1n2's own S1-U uplink receive TEID (host byte order)
    bool has_s1n2_uplink_teid;                 // Whether s1n2 uplink TEID is allocated and stored

    // TAU (Tracking Area Update) handling flags
    bool in_tau_procedure;                     // UE is currently in TAU procedure
    bool preserve_teid_mapping;                // Preserve TEID mapping during and after TAU
    time_t tau_start_time;                     // When TAU procedure started

    // Cached 5GS registration context for TAU-driven mobility updates
    bool has_last_registration_result;         // Whether registration_result buffer is valid
    uint8_t last_registration_result[8];       // Raw TLV payload from Registration Accept
    uint8_t last_registration_result_len;      // Length of registration_result payload
    bool has_last_5g_guti;                     // Last 5G-GUTI mobile identity available
    uint8_t last_5g_guti[32];                  // Cached 5G-GUTI mobile identity payload
    uint8_t last_5g_guti_len;                  // Length of cached 5G-GUTI payload
    bool has_last_ngksi_5g;                    // Cached ngKSI value available
    uint8_t last_ngksi_5g;                     // Cached ngKSI (3-bit value)
    uint8_t last_ngksi_tsc_5g;                 // Cached ngKSI TSC bit
    bool has_last_access_type;                 // Cached access type from registration result
    uint8_t last_5gs_access_type;              // Access type bits (3GPP, non-3GPP, both)
    // 恒久KSI一貫性用: 直前のDL NASで使ったngKSI
    uint8_t last_dl_ngksi;
} ue_id_mapping_t;

// Converter context
typedef struct s1n2_context {
    int s1c_fd;
    int n2_fd;
    int s1u_fd;
    int n3_fd;
    struct sockaddr_in s1c_addr;
    struct sockaddr_in n2_addr;
    struct sockaddr_in s1u_addr;
    struct sockaddr_in n3_addr;
    bool n2_connected;
    bool n2_connection_attempted;
    time_t n2_retry_time;

    // GTP-U TEID mapping
    teid_mapping_t teid_mappings[16];  // Support up to 16 mappings
    int num_mappings;
    uint32_t next_n3_teid;  // Next available N3 TEID

    // UE ID correlation between S1 and N2 interfaces
    ue_id_mapping_t ue_mappings[S1N2_MAX_UE_MAPPINGS];
    size_t num_ue_mappings;
    long next_ran_ue_ngap_id;

    // E-RAB to PDU Session mapping
    e_rab_setup_info_t e_rab_contexts[16];  // Support up to 16 E-RAB contexts
    int num_e_rab_contexts;
    uint8_t next_pdu_session_id;  // Next available PDU Session ID

    // One-shot NGSetupRequest sent flag
    bool ngsetup_sent;

    // Deferred S1SetupRequest handling
    deferred_s1setup_t pending_s1setup;
    bool has_pending_s1setup;

    // Authentication context for RES* computation (forward declaration)
    void *auth_ctx;
} s1n2_context_t;

// Function declarations
int s1n2_convert_s1setup_to_ngsetup(uint8_t *s1ap_data, size_t s1ap_len,
                                   uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_ngsetup_to_s1setup(uint8_t *ngap_data, size_t ngap_len,
                                   uint8_t *s1ap_data, size_t *s1ap_len);
int s1n2_convert_initial_ue_message(uint8_t *s1ap_data, size_t s1ap_len,
                                   uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_downlink_nas_transport(s1n2_context_t *ctx,
                                       uint8_t *s1ap_data, size_t s1ap_len,
                                       uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_uplink_nas_transport(s1n2_context_t *ctx, uint8_t *s1ap_data, size_t s1ap_len,
                                     uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_initial_context_setup_request(uint8_t *s1ap_data, size_t s1ap_len,
                                              uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_initial_context_setup_request_enhanced(s1n2_context_t *ctx, uint8_t *s1ap_data, size_t s1ap_len,
                                                       uint8_t *ngap_data, size_t *ngap_len);
int s1n2_convert_initial_context_setup_response(uint8_t *s1ap_data, size_t s1ap_len,
                                               uint8_t *ngap_data, size_t *ngap_len,
                                               s1n2_context_t *ctx);

void s1n2_register_auth_context(s1n2_context_t *ctx, s1n2_auth_context_t *auth_ctx);

int s1n2_handle_s1c_message(s1n2_context_t *ctx, uint8_t *data, size_t len);
int s1n2_handle_n2_message(s1n2_context_t *ctx, uint8_t *data, size_t len);
int s1n2_process_pending_s1setup(s1n2_context_t *ctx);

// E-RAB management functions
int s1n2_add_e_rab_context(s1n2_context_t *ctx, const e_rab_setup_info_t *e_rab_info);
int s1n2_find_e_rab_context(s1n2_context_t *ctx, uint8_t e_rab_id, e_rab_setup_info_t **e_rab_info);
int s1n2_remove_e_rab_context(s1n2_context_t *ctx, uint8_t e_rab_id);
int s1n2_extract_e_rab_setup_from_s1ap(uint8_t *s1ap_data, size_t s1ap_len, e_rab_setup_info_t *e_rab_info);

// TEID mapping functions
int s1n2_init_context(s1n2_context_t *ctx);
int s1n2_health_check(s1n2_context_t *ctx);
void s1n2_cleanup_context(s1n2_context_t *ctx);
int build_ngsetup_request_dynamic(uint8_t *buf, size_t *len);
// NGAP dynamic builder with explicit args (MCC/MNC/TAC/gNB-ID/Name)
int build_ngsetup_request_args(
    uint8_t *buf,
    size_t *len,
    const char *mcc,
    const char *mnc,
    long tac,
    uint32_t gnb_id,
    const char *ran_name);

// NGAP message builders
int build_ngsetup_request(uint8_t *buf, size_t *len, const char *mcc, const char *mnc, long tac, uint32_t gnb_id, const char *ran_name);
int build_initial_ue_message(uint8_t *buf, size_t *len,
    uint32_t ran_ue_ngap_id, const uint8_t *nas_pdu, size_t nas_pdu_len,
    const char *mcc, const char *mnc, long tac, uint32_t nr_cell_id,
    uint8_t rrc_cause, bool include_s_tmsi, uint32_t amf_set_id,
    uint8_t amf_pointer, uint32_t fiveg_tmsi, bool ue_context_requested);

#endif // S1N2_CONVERTER_H
