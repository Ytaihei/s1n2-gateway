#ifndef S1N2_AUTH_H
#define S1N2_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>

// Authentication Vector structure
typedef struct s1n2_auth_vector_s {
    uint8_t rand[16];          // Random challenge (128 bits)
    uint8_t autn[16];          // Authentication token (128 bits)
    uint8_t xres[16];          // Expected response (typically 8-16 bytes)
    uint8_t xres_len;          // Length of XRES
    uint8_t ck[16];            // Cipher key (128 bits)
    uint8_t ik[16];            // Integrity key (128 bits)
    uint8_t kausf[32];         // Key for AUSF (256 bits)
    uint8_t res_star[16];      // Expected RES* (128 bits)
    time_t timestamp;          // Creation time
    bool valid;                // Vector is valid
    char imsi[16];             // Associated IMSI
} s1n2_auth_vector_t;

// Subscriber authentication keys
typedef struct s1n2_subscriber_keys_s {
    char imsi[16];             // IMSI
    uint8_t ki[16];            // Permanent subscriber key (128 bits)
    uint8_t opc[16];           // Operator variant key (128 bits)
    bool configured;           // Keys are configured
} s1n2_subscriber_keys_t;

// RES*/XRES* KDF mode (TS 33.501 Annex A.4)
typedef enum {
    RES_STAR_KDF_STANDARD = 0,      // Use Kausf as key (TS 33.501 compliant)
    RES_STAR_KDF_OPEN5GS_COMPAT = 1 // Use CK||IK as key (Open5GS v2.7.2 bug compatibility)
} res_star_kdf_mode_t;

// Authentication context
typedef struct s1n2_auth_context_s {
    s1n2_subscriber_keys_t subscribers[32];  // Max 32 subscribers
    int subscriber_count;
    s1n2_auth_vector_t auth_cache[64];       // Max 64 cached vectors
    bool enabled;
    bool audit_logging;
    bool auto_clear_keys;
    int max_cache_time;
    bool xor_to_milenage_conversion;         // Enable XOR→Milenage conversion for test eSIMs
    res_star_kdf_mode_t res_star_kdf_mode;   // RES*/XRES* KDF implementation mode
} s1n2_auth_context_t;

// Initialize authentication context
int s1n2_auth_init(s1n2_auth_context_t *auth_ctx, const char *config_file);

// Load subscriber keys from configuration file
int s1n2_auth_load_keys(s1n2_auth_context_t *auth_ctx, const char *config_file);

// Get subscriber keys by IMSI
s1n2_subscriber_keys_t* s1n2_auth_get_keys(s1n2_auth_context_t *auth_ctx, const char *imsi);

// Compute authentication vector for 5G from RAND
int s1n2_auth_compute_vector(s1n2_auth_context_t *auth_ctx,
                              const char *imsi,
                              const uint8_t *rand,
                              s1n2_auth_vector_t *av);

// Compute RES* from 4G RES with IMSI (recommended method)
int s1n2_auth_compute_res_star_with_imsi(s1n2_auth_context_t *auth_ctx,
                                          const char *imsi,
                                          const uint8_t *rand,
                                          const uint8_t *sqn_xor_ak,
                                          const uint8_t *res_4g,
                                          uint8_t res_4g_len,
                                          uint8_t *res_star);

// Compute RES* from 4G RES using cached authentication vector
int s1n2_auth_compute_res_star(s1n2_auth_context_t *auth_ctx,
                                const uint8_t *rand,
                                const uint8_t *res_4g,
                                uint8_t res_4g_len,
                                uint8_t *res_star);

// Cache authentication vector
int s1n2_auth_cache_vector(s1n2_auth_context_t *auth_ctx,
                            s1n2_auth_vector_t *av);

// Get cached authentication vector by RAND
s1n2_auth_vector_t* s1n2_auth_get_cached_vector(s1n2_auth_context_t *auth_ctx,
                                                 const uint8_t *rand);

// Clear cached authentication vector
void s1n2_auth_clear_vector(s1n2_auth_context_t *auth_ctx, const uint8_t *rand);

// Clear all expired cached vectors
void s1n2_auth_clear_expired(s1n2_auth_context_t *auth_ctx);

// Cleanup authentication context
void s1n2_auth_cleanup(s1n2_auth_context_t *auth_ctx);

// Milenage f1-f5 functions (3GPP TS 35.206)
void s1n2_milenage_f1(const uint8_t *opc, const uint8_t *k,
                      const uint8_t *rand, const uint8_t *sqn, const uint8_t *amf,
                      uint8_t *mac_a);

void s1n2_milenage_f2345(const uint8_t *opc, const uint8_t *k,
                         const uint8_t *rand,
                         uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);

// 5G KDF functions (3GPP TS 33.501)
int s1n2_kdf_kausf(const uint8_t *ck, const uint8_t *ik,
                   const uint8_t *sqn_xor_ak,
                   const char *serving_network_name,
                   uint8_t *kausf);

int s1n2_kdf_res_star(const uint8_t *ck,
                      const uint8_t *ik,
                      const char *serving_network_name,
                      const uint8_t *rand,
                      const uint8_t *res, uint8_t res_len,
                      uint8_t *res_star);

// Derive RES* from Kausf (3GPP TS 33.501 Annex A.4) - CORRECT IMPLEMENTATION
int s1n2_kdf_res_star_from_kausf(const uint8_t *kausf,  // 32 bytes
                                  const char *serving_network_name,
                                  const uint8_t *rand,    // 16 bytes
                                  const uint8_t *res, uint8_t res_len,
                                  uint8_t *res_star);     // 16 bytes output

// Derive Kseaf from Kausf (3GPP TS 33.501 Annex A.6)
int s1n2_kdf_kseaf(const uint8_t *kausf,              // 32 bytes
                   const char *serving_network_name,  // e.g., "5G:mnc001.mcc001.3gppnetwork.org"
                   uint8_t *kseaf);                   // 32 bytes output

// Derive Kamf from Kseaf (3GPP TS 33.501 Annex A.7)
int s1n2_kdf_kamf(const uint8_t *kseaf,      // 32 bytes
                  const char *supi,           // SUPI (e.g., "imsi-001011234567895")
                  const uint8_t *abba,        // ABBA (2 bytes)
                  uint8_t abba_len,           // Length of ABBA
                  uint8_t *kamf);             // 32 bytes output

// Derive 5G NAS keys from Kamf (3GPP TS 33.501 Annex A.8)
int s1n2_kdf_nas_5g(const uint8_t *kamf,        // 32 bytes
                    uint8_t algorithm_type,      // 0x01=integrity, 0x02=encryption
                    uint8_t algorithm_id,        // Algorithm ID (e.g., 2 for 128-5G-IA2)
                    uint8_t *key_out);           // 16 bytes output

// 4G KDF functions (3GPP TS 33.401)
// Derive K_ASME from CK, IK (EPS key hierarchy)
int s1n2_kdf_kasme(const uint8_t *ck,        // 16 bytes
                   const uint8_t *ik,        // 16 bytes
                   const uint8_t *sqn_xor_ak, // 6 bytes
                   const uint8_t *plmn_id,   // 3 bytes (MCC+MNC)
                   uint8_t *kasme);          // 32 bytes output

// Derive K_NASint or K_NASenc from K_ASME
int s1n2_kdf_nas_keys(const uint8_t *kasme,    // 32 bytes
                      uint8_t algorithm_type,   // 0x01 for integrity, 0x02 for encryption
                      uint8_t algorithm_id,     // Algorithm identifier (e.g., 2 for EIA2/EEA2)
                      uint8_t *key_out);        // 16 bytes output (K_NASint or K_NASenc)

// Helper: Derive both K_NASint and K_NASenc at once
int s1n2_derive_4g_nas_keys(const uint8_t *k,         // Ki (16 bytes)
                            const uint8_t *opc,       // OPc (16 bytes)
                            const uint8_t *rand,      // RAND (16 bytes)
                            const uint8_t *sqn_xor_ak, // SQN^AK (6 bytes)
                            const uint8_t *plmn_id,   // PLMN ID (3 bytes)
                            uint8_t int_alg,          // Integrity algorithm ID
                            uint8_t enc_alg,          // Encryption algorithm ID
                            uint8_t *k_nas_int,       // Output: K_NASint (16 bytes)
                            uint8_t *k_nas_enc);      // Output: K_NASenc (16 bytes)

// Derive KeNB from KASME (3GPP TS 33.401 Annex A.3)
int s1n2_kdf_kenb(const uint8_t *kasme,    // KASME (32 bytes)
                  uint32_t ul_count,        // Uplink NAS COUNT (32-bit)
                  uint8_t *kenb);           // Output: KeNB (32 bytes)

// Decode UE's expected SQN from AUTS (3GPP TS 33.102)
int s1n2_decode_auts_sqn(const uint8_t *opc,     // OPc (16 bytes)
                         const uint8_t *k,        // Ki (16 bytes)
                         const uint8_t *rand,     // RAND (16 bytes)
                         const uint8_t *auts,     // AUTS (14 bytes)
                         uint8_t *sqn_ms);        // Output: UE's SQN (6 bytes)

#endif // S1N2_AUTH_H
