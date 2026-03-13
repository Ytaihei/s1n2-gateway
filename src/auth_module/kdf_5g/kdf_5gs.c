/**
 * @file kdf_5gs.c
 * @brief 5G Security Key Derivation Functions (3GPP TS 33.501)
 *
 * Implements:
 *   - Kausf derivation (Annex A.2)
 *   - RES* / XRES* derivation (Annex A.4) — standard and Open5GS compat
 *   - Kseaf derivation (Annex A.6)
 *   - Kamf derivation (Annex A.7)
 *   - 5G NAS key derivation (Annex A.8)
 *   - RES* computation with IMSI (high-level convenience)
 */
#include "kdf_5gs.h"
#include "subscriber_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define LOG_TAG "[s1n2_auth]"

/* Forward declarations — from other auth modules */
extern void s1n2_auth_bytes_to_hex(const uint8_t *bytes, size_t bytes_len, char *hex_str);
extern void s1n2_milenage_f2345(const uint8_t *opc, const uint8_t *k,
                                const uint8_t *rand,
                                uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);
extern s1n2_subscriber_keys_t* s1n2_auth_get_keys(s1n2_auth_context_t *auth_ctx, const char *imsi);

/* ------------------------------------------------------------------ */
/* Kausf derivation (TS 33.501 Annex A.2)                             */
/* ------------------------------------------------------------------ */

int s1n2_kdf_kausf(const uint8_t *ck, const uint8_t *ik,
                   const uint8_t *sqn_xor_ak,
                   const char *serving_network_name,
                   uint8_t *kausf) {
    if (!ck || !ik || !sqn_xor_ak || !serving_network_name || !kausf) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_kausf\n", LOG_TAG);
        return -1;
    }

    uint8_t key[32];
    memcpy(key, ck, 16);
    memcpy(key + 16, ik, 16);

    uint8_t input[256];
    size_t offset = 0;

    input[offset++] = 0x6A; /* FC */

    size_t sn_len = strlen(serving_network_name);
    memcpy(&input[offset], serving_network_name, sn_len);
    offset += sn_len;
    uint16_t sn_length = (uint16_t)sn_len;
    input[offset++] = (sn_length >> 8) & 0xFF;
    input[offset++] = sn_length & 0xFF;

    memcpy(&input[offset], sqn_xor_ak, 6);
    offset += 6;
    uint16_t sqn_length = 6;
    input[offset++] = (sqn_length >> 8) & 0xFF;
    input[offset++] = sqn_length & 0xFF;

    size_t sn_len_dbg = strlen(serving_network_name);
    printf("%s [DEBUG] kdf_kausf inputs: SNN(len=%zu, head='%.*s'), SQN^AK(len=6)\n",
        LOG_TAG,
        sn_len_dbg,
        (int)((sn_len_dbg > 16) ? 16 : sn_len_dbg),
        serving_network_name);

    printf("%s [TRACE] Kausf derivation:\n", LOG_TAG);
    printf("%s [TRACE]   Key (CK||IK, 32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", key[i]);
    printf("\n");
    printf("%s [TRACE]   FC: 0x%02X\n", LOG_TAG, input[0]);
    printf("%s [TRACE]   SNN: %s (len=%zu)\n", LOG_TAG, serving_network_name, sn_len);
    printf("%s [TRACE]   SQN^AK: ", LOG_TAG);
    for (int i = 0; i < 6; i++) printf("%02X", sqn_xor_ak[i]);
    printf("\n");

    unsigned int kausf_len = 32;
    uint8_t *result = HMAC(EVP_sha256(), key, sizeof(key), input, offset, kausf, &kausf_len);

    if (!result || kausf_len != 32) {
        fprintf(stderr, "%s ERROR: Failed to compute Kausf\n", LOG_TAG);
        return -1;
    }

    printf("%s [TRACE] Computed Kausf (32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", kausf[i]);
    printf("\n");
    printf("%s INFO: Computed Kausf (head 8B): ", LOG_TAG);
    for (int i = 0; i < 8; i++) printf("%02X", kausf[i]);
    printf("..\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* RES* from Kausf (TS 33.501 Annex A.4) — standard                  */
/* ------------------------------------------------------------------ */

int s1n2_kdf_res_star_from_kausf(const uint8_t *kausf,
                                  const char *serving_network_name,
                                  const uint8_t *rand,
                                  const uint8_t *res, uint8_t res_len,
                                  uint8_t *res_star) {
    if (!kausf || !serving_network_name || !rand || !res || !res_star) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_res_star_from_kausf\n", LOG_TAG);
        return -1;
    }

    if (res_len < 4 || res_len > 16) {
        fprintf(stderr, "%s ERROR: Invalid RES length: %u\n", LOG_TAG, res_len);
        return -1;
    }

    size_t sn_len = strlen(serving_network_name);
    if (sn_len == 0 || sn_len > 200) {
        fprintf(stderr, "%s ERROR: Invalid serving network length: %zu\n", LOG_TAG, sn_len);
        return -1;
    }

    uint8_t input[256];
    size_t offset = 0;

    input[offset++] = 0x6B;

    memcpy(&input[offset], serving_network_name, sn_len);
    offset += sn_len;
    uint16_t sn_length = (uint16_t)sn_len;
    input[offset++] = (sn_length >> 8) & 0xFF;
    input[offset++] = sn_length & 0xFF;

    memcpy(&input[offset], rand, 16);
    offset += 16;
    uint16_t rand_length = 16;
    input[offset++] = (rand_length >> 8) & 0xFF;
    input[offset++] = rand_length & 0xFF;

    memcpy(&input[offset], res, res_len);
    offset += res_len;
    uint16_t res_length = res_len;
    input[offset++] = (res_length >> 8) & 0xFF;
    input[offset++] = res_length & 0xFF;

    printf("%s [TRACE] RES* derivation (TS 33.501 Annex A.4):\n", LOG_TAG);
    printf("%s [TRACE]   Key (Kausf, 32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", kausf[i]);
    printf("\n");
    printf("%s [TRACE]   FC: 0x%02X\n", LOG_TAG, input[0]);
    printf("%s [TRACE]   P0 (SNN): %s (len=%zu)\n", LOG_TAG, serving_network_name, sn_len);
    printf("%s [TRACE]   P1 (RAND, 16 bytes): ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", rand[i]);
    printf("\n");
    printf("%s [TRACE]   P2 (RES, %u bytes): ", LOG_TAG, res_len);
    for (int i = 0; i < res_len; i++) printf("%02X", res[i]);
    printf("\n");

    uint8_t temp[32];
    unsigned int temp_len = sizeof(temp);
    uint8_t *result = HMAC(EVP_sha256(), kausf, 32, input, offset, temp, &temp_len);

    if (!result || temp_len != sizeof(temp)) {
        fprintf(stderr, "%s ERROR: Failed to compute RES* from Kausf\n", LOG_TAG);
        return -1;
    }

    printf("%s [TRACE]   HMAC-SHA-256 output (32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", temp[i]);
    printf("\n");

    /* Take the last 128 bits (16 bytes) as RES* */
    memcpy(res_star, temp + 16, 16);

    char hex_res_star[33];
    s1n2_auth_bytes_to_hex(res_star, 16, hex_res_star);
    printf("%s INFO: Computed RES* (from Kausf): %s\n", LOG_TAG, hex_res_star);

    return 0;
}

/* ------------------------------------------------------------------ */
/* RES* from CK||IK (Open5GS v2.7.2 bug compatibility)               */
/* ------------------------------------------------------------------ */

int s1n2_kdf_res_star_from_ck_ik(const uint8_t *ck, const uint8_t *ik,
                                  const char *serving_network_name,
                                  const uint8_t *rand,
                                  const uint8_t *res, uint8_t res_len,
                                  uint8_t *res_star) {
    if (!ck || !ik || !serving_network_name || !rand || !res || !res_star) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_res_star_from_ck_ik\n", LOG_TAG);
        return -1;
    }

    if (res_len < 4 || res_len > 16) {
        fprintf(stderr, "%s ERROR: Invalid RES length: %u\n", LOG_TAG, res_len);
        return -1;
    }

    size_t sn_len = strlen(serving_network_name);
    if (sn_len == 0 || sn_len > 200) {
        fprintf(stderr, "%s ERROR: Invalid serving network length: %zu\n", LOG_TAG, sn_len);
        return -1;
    }

    /* Open5GS v2.7.2 bug: Uses CK||IK instead of Kausf */
    uint8_t key_ck_ik[32];
    memcpy(key_ck_ik, ck, 16);
    memcpy(key_ck_ik + 16, ik, 16);

    uint8_t input[256];
    size_t offset = 0;

    input[offset++] = 0x6B;

    memcpy(&input[offset], serving_network_name, sn_len);
    offset += sn_len;
    uint16_t sn_length = (uint16_t)sn_len;
    input[offset++] = (sn_length >> 8) & 0xFF;
    input[offset++] = sn_length & 0xFF;

    memcpy(&input[offset], rand, 16);
    offset += 16;
    uint16_t rand_length = 16;
    input[offset++] = (rand_length >> 8) & 0xFF;
    input[offset++] = rand_length & 0xFF;

    memcpy(&input[offset], res, res_len);
    offset += res_len;
    uint16_t res_length = res_len;
    input[offset++] = (res_length >> 8) & 0xFF;
    input[offset++] = res_length & 0xFF;

    printf("%s [TRACE] RES* derivation (Open5GS v2.7.2 bug compatibility mode):\n", LOG_TAG);
    printf("%s [TRACE]   Key (CK||IK, 32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", key_ck_ik[i]);
    printf("\n");
    printf("%s [TRACE]   **WARNING**: Using CK||IK instead of Kausf (non-standard!)\n", LOG_TAG);
    printf("%s [TRACE]   FC: 0x%02X\n", LOG_TAG, input[0]);
    printf("%s [TRACE]   P0 (SNN): %s (len=%zu)\n", LOG_TAG, serving_network_name, sn_len);
    printf("%s [TRACE]   P1 (RAND, 16 bytes): ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", rand[i]);
    printf("\n");
    printf("%s [TRACE]   P2 (RES, %u bytes): ", LOG_TAG, res_len);
    for (int i = 0; i < res_len; i++) printf("%02X", res[i]);
    printf("\n");

    uint8_t temp[32];
    unsigned int temp_len = sizeof(temp);
    uint8_t *result = HMAC(EVP_sha256(), key_ck_ik, 32, input, offset, temp, &temp_len);

    if (!result || temp_len != sizeof(temp)) {
        fprintf(stderr, "%s ERROR: Failed to compute RES* from CK||IK\n", LOG_TAG);
        return -1;
    }

    printf("%s [TRACE]   HMAC-SHA-256 output (32 bytes): ", LOG_TAG);
    for (int i = 0; i < 32; i++) printf("%02X", temp[i]);
    printf("\n");

    memcpy(res_star, temp + 16, 16);

    char hex_res_star[33];
    s1n2_auth_bytes_to_hex(res_star, 16, hex_res_star);
    printf("%s INFO: Computed RES* (from CK||IK, Open5GS compat mode): %s\n", LOG_TAG, hex_res_star);

    return 0;
}

/* ------------------------------------------------------------------ */
/* Kseaf derivation (TS 33.501 Annex A.6)                             */
/* ------------------------------------------------------------------ */

int s1n2_kdf_kseaf(const uint8_t *kausf,
                   const char *serving_network_name,
                   uint8_t *kseaf) {
    if (!kausf || !serving_network_name || !kseaf) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_kseaf\n", LOG_TAG);
        return -1;
    }

    size_t sn_len = strlen(serving_network_name);
    if (sn_len == 0 || sn_len > 200) {
        fprintf(stderr, "%s ERROR: Invalid serving network length: %zu\n", LOG_TAG, sn_len);
        return -1;
    }

    uint8_t input[256];
    size_t offset = 0;

    input[offset++] = 0x6C;

    memcpy(&input[offset], serving_network_name, sn_len);
    offset += sn_len;
    uint16_t sn_length = (uint16_t)sn_len;
    input[offset++] = (sn_length >> 8) & 0xFF;
    input[offset++] = sn_length & 0xFF;

    unsigned int kseaf_len = 32;
    uint8_t *result = HMAC(EVP_sha256(), kausf, 32, input, offset, kseaf, &kseaf_len);

    if (!result || kseaf_len != 32) {
        fprintf(stderr, "%s ERROR: Failed to compute Kseaf\n", LOG_TAG);
        return -1;
    }

    printf("%s [DEBUG] Kseaf derived successfully (head 8B): ", LOG_TAG);
    for (int i = 0; i < 8; i++) printf("%02X", kseaf[i]);
    printf("..\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* Kamf derivation (TS 33.501 Annex A.7)                              */
/* ------------------------------------------------------------------ */

int s1n2_kdf_kamf(const uint8_t *kseaf,
                  const char *supi,
                  const uint8_t *abba,
                  uint8_t abba_len,
                  uint8_t *kamf) {
    if (!kseaf || !supi || !abba || !kamf) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_kamf\n", LOG_TAG);
        return -1;
    }

    if (abba_len < 2 || abba_len > 256) {
        fprintf(stderr, "%s ERROR: Invalid ABBA length: %u\n", LOG_TAG, abba_len);
        return -1;
    }

    size_t supi_len = strlen(supi);
    if (supi_len == 0 || supi_len > 200) {
        fprintf(stderr, "%s ERROR: Invalid SUPI length: %zu\n", LOG_TAG, supi_len);
        return -1;
    }

    uint8_t input[512];
    size_t offset = 0;

    /* Open5GS の ogs_kdf_kamf と同様、SUPI 文字列の値部分のみを KDF に使用する。 */
    const char *supi_value = supi;
    if (supi_value) {
        if (strncasecmp(supi_value, "imsi-", 5) == 0) {
            supi_value += 5;
        } else if (strncasecmp(supi_value, "nai-", 4) == 0) {
            supi_value += 4;
        }
    }

    input[offset++] = 0x6D;

    size_t supi_value_len = supi_value ? strlen(supi_value) : 0;
    memcpy(&input[offset], supi_value ? (const uint8_t*)supi_value : (const uint8_t*)supi, supi_value_len ? supi_value_len : supi_len);
    offset += (supi_value_len ? supi_value_len : supi_len);
    uint16_t supi_length = (uint16_t)(supi_value_len ? supi_value_len : supi_len);
    input[offset++] = (supi_length >> 8) & 0xFF;
    input[offset++] = supi_length & 0xFF;

    memcpy(&input[offset], abba, abba_len);
    offset += abba_len;
    uint16_t abba_length = (uint16_t)abba_len;
    input[offset++] = (abba_length >> 8) & 0xFF;
    input[offset++] = abba_length & 0xFF;

    unsigned int kamf_len = 32;
    uint8_t *result = HMAC(EVP_sha256(), kseaf, 32, input, offset, kamf, &kamf_len);

    if (!result || kamf_len != 32) {
        fprintf(stderr, "%s ERROR: Failed to compute Kamf\n", LOG_TAG);
        return -1;
    }

    printf("%s [DEBUG] kdf_kamf inputs: SUPI='%s' (value='%s'), ABBA(len=%u): ",
        LOG_TAG, supi, supi_value ? supi_value : "(null)", abba_len);
    for (int i = 0; i < abba_len && i < 8; i++) printf("%02X", abba[i]);
    if (abba_len > 8) printf("..");
    printf("\n");
    printf("%s [DEBUG] Kamf derived successfully (head 8B): ", LOG_TAG);
    for (int i = 0; i < 8; i++) printf("%02X", kamf[i]);
    printf("..\n");

    return 0;
}

/* ------------------------------------------------------------------ */
/* 5G NAS key derivation (TS 33.501 Annex A.8)                        */
/* ------------------------------------------------------------------ */

int s1n2_kdf_nas_5g(const uint8_t *kamf,
                    uint8_t algorithm_type,
                    uint8_t algorithm_id,
                    uint8_t *key_out) {
    if (!kamf || !key_out) {
        fprintf(stderr, "%s ERROR: NULL parameter in kdf_nas_5g\n", LOG_TAG);
        return -1;
    }

    const uint8_t fc = 0x69;

    uint8_t algo_type_dist = algorithm_type;
    uint8_t algo_id = algorithm_id;

    uint8_t input[16];
    size_t offset = 0;

    input[offset++] = fc;
    input[offset++] = algo_type_dist;
    input[offset++] = 0x00;  /* L0 high byte */
    input[offset++] = 0x01;  /* L0 low byte */
    input[offset++] = algo_id;
    input[offset++] = 0x00;  /* L1 high byte */
    input[offset++] = 0x01;  /* L1 low byte */

    uint8_t output[32];
    unsigned int output_len = sizeof(output);
    uint8_t *result = HMAC(EVP_sha256(), kamf, 32, input, offset, output, &output_len);

    if (!result || output_len != 32) {
        fprintf(stderr, "%s ERROR: Failed to compute 5G NAS key\n", LOG_TAG);
        return -1;
    }

    /* Optional deep debug */
    const char *alt_dbg = getenv("S1N2_NAS5G_DEBUG_ALT");
    if (alt_dbg && (*alt_dbg == '1' || *alt_dbg == 'y' || *alt_dbg == 'Y')) {
        printf("%s [DEBUG] NAS5G-KDF input(%zuB): ", LOG_TAG, offset);
        for (size_t i = 0; i < offset; ++i) printf("%02X", input[i]);
        printf("  (FC=0x69, type=0x%02X, id=0x%02X)\n", algorithm_type, algorithm_id);

        uint8_t tmp_out[32];
        unsigned int tmp_len = sizeof(tmp_out);

        #define NAS5G_SHOW_VARIANT(TYP, OFF) \
            do { \
                uint8_t in2[16]; size_t of2 = 0; \
                in2[of2++] = 0x69; \
                in2[of2++] = (uint8_t)(TYP); \
                in2[of2++] = 0x00; in2[of2++] = 0x01; \
                in2[of2++] = algorithm_id; \
                in2[of2++] = 0x00; in2[of2++] = 0x01; \
                tmp_len = sizeof(tmp_out); \
                if (!HMAC(EVP_sha256(), kamf, 32, in2, of2, tmp_out, &tmp_len) || tmp_len != 32) break; \
                printf("%s [DEBUG] NAS5G variant type=0x%02X, off=%d head8=", LOG_TAG, (uint8_t)(TYP), (int)(OFF)); \
                for (int vi = 0; vi < 8; ++vi) printf("%02X", tmp_out[(OFF)+vi]); \
                printf("..\n"); \
            } while (0)

        NAS5G_SHOW_VARIANT(0x01, 0);
        NAS5G_SHOW_VARIANT(0x01, 16);
        NAS5G_SHOW_VARIANT(0x02, 0);
        NAS5G_SHOW_VARIANT(0x02, 16);
        #undef NAS5G_SHOW_VARIANT
    }

    /* Per TS 33.501 A.8 and Open5GS implementation, take bytes [16:31] */
    memcpy(key_out, output + 16, 16);

    printf("%s [DEBUG] 5G NAS key derived (type=0x%02X, alg=%u, head 8B): ",
        LOG_TAG, algorithm_type, algorithm_id);
    for (int i = 0; i < 8; i++) printf("%02X", key_out[i]);
    printf("..\n");

    memset(output, 0, sizeof(output));

    return 0;
}

/* ------------------------------------------------------------------ */
/* RES* computation with IMSI (high-level convenience)                */
/* ------------------------------------------------------------------ */

int s1n2_auth_compute_res_star_with_imsi(s1n2_auth_context_t *auth_ctx,
                                          const char *imsi,
                                          const uint8_t *rand,
                                          const uint8_t *sqn_xor_ak,
                                          const uint8_t *res_4g,
                                          uint8_t res_4g_len,
                                          uint8_t *res_star) {
    if (!auth_ctx || !imsi || !rand || !sqn_xor_ak || !res_4g || !res_star) {
        fprintf(stderr, "%s ERROR: NULL parameter in compute_res_star_with_imsi\n", LOG_TAG);
        return -1;
    }

    printf("%s INFO: Computing RES* for IMSI=%s\n", LOG_TAG, imsi);

    s1n2_subscriber_keys_t *keys = s1n2_auth_get_keys(auth_ctx, imsi);
    if (!keys || !keys->configured) {
        fprintf(stderr, "%s ERROR: No keys configured for IMSI: %s\n", LOG_TAG, imsi);
        return -1;
    }

    uint8_t ck[16], ik[16];
    uint8_t res_computed[8];
    uint8_t ak[6];

    bool use_xor_conversion = auth_ctx->xor_to_milenage_conversion;

    if (use_xor_conversion && res_4g_len == 8) {
        printf("%s INFO: XOR Algorithm Conversion Mode ENABLED\n", LOG_TAG);
        printf("%s      Deriving Ki from XOR RES and converting to Milenage\n", LOG_TAG);

        uint8_t ki_derived[16];
        memcpy(ki_derived, keys->ki, 16);

        for (int i = 0; i < 8; i++) {
            ki_derived[i] = res_4g[i] ^ rand[i];
        }

        printf("%s [TRACE] Derived Ki from XOR: ", LOG_TAG);
        for (int i = 0; i < 16; i++) printf("%02X", ki_derived[i]);
        printf("\n");

        s1n2_milenage_f2345(keys->opc, ki_derived, rand, res_computed, ck, ik, ak);

        printf("%s INFO: Converted XOR RES to Milenage RES\n", LOG_TAG);
    } else {
        s1n2_milenage_f2345(keys->opc, keys->ki, rand, res_computed, ck, ik, ak);
    }

    printf("%s INFO: Computed CK, IK, and RES from Ki+RAND using Milenage\n", LOG_TAG);
    printf("%s [TRACE] Ki:  ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", keys->ki[i]);
    printf("\n");
    printf("%s [TRACE] OPc: ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", keys->opc[i]);
    printf("\n");
    printf("%s [TRACE] RAND:", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", rand[i]);
    printf("\n");
    printf("%s [TRACE] Computed CK (16 bytes): ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", ck[i]);
    printf("\n");
    printf("%s [TRACE] Computed IK (16 bytes): ", LOG_TAG);
    for (int i = 0; i < 16; i++) printf("%02X", ik[i]);
    printf("\n");
    printf("%s DEBUG: Computed RES (8 bytes): ", LOG_TAG);
    for (int i = 0; i < 8; i++) {
        printf("%02X", res_computed[i]);
    }
    printf("\n");
    printf("%s DEBUG: Received 4G UE RES (%u bytes): ", LOG_TAG, res_4g_len);
    for (int i = 0; i < res_4g_len && i < 16; i++) {
        printf("%02X", res_4g[i]);
    }
    printf("\n");

    if (res_4g_len == 8) {
        if (memcmp(res_computed, res_4g, 8) != 0) {
            printf("%s ERROR: 4G UE RES does NOT match Milenage RES computed from configured Ki/OPc\n", LOG_TAG);
            printf("%s        This indicates a subscriber key mismatch between s1n2 and UE/UDM.\n", LOG_TAG);
            printf("%s        Fix by aligning Ki/OPc for IMSI=%s in %s (or environment variables).\n", LOG_TAG, imsi, "AUTH_CONFIG_FILE");
            printf("%s        RES_computed: ", LOG_TAG);
            for (int i = 0; i < 8; i++) printf("%02X", res_computed[i]);
            printf("  UE_RES: ");
            for (int i = 0; i < 8; i++) printf("%02X", res_4g[i]);
            printf("\n");
        } else {
            printf("%s INFO: 4G UE RES matches Milenage output — Ki/OPc parity looks OK.\n", LOG_TAG);
        }
    }

    printf("%s DEBUG: Using SQN^AK from AUTN: ", LOG_TAG);
    for (int i = 0; i < 6; i++) {
        printf("%02X", sqn_xor_ak[i]);
    }
    printf("\n");

    uint8_t kausf[32];
    const char *serving_network = "5G:mnc001.mcc001.3gppnetwork.org";

    if (s1n2_kdf_kausf(ck, ik, sqn_xor_ak, serving_network, kausf) != 0) {
        fprintf(stderr, "%s ERROR: Failed to compute Kausf\n", LOG_TAG);
        return -1;
    }

    printf("%s INFO: Computed Kausf from CK||IK\n", LOG_TAG);

    int kdf_result = -1;
    if (auth_ctx->res_star_kdf_mode == RES_STAR_KDF_OPEN5GS_COMPAT) {
        printf("%s INFO: Using Open5GS compatibility mode (CK||IK-based KDF)\n", LOG_TAG);
        kdf_result = s1n2_kdf_res_star_from_ck_ik(ck, ik, serving_network, rand, res_computed, 8, res_star);
    } else {
        printf("%s INFO: Using standard TS 33.501 mode (Kausf-based KDF)\n", LOG_TAG);
        kdf_result = s1n2_kdf_res_star_from_kausf(kausf, serving_network, rand, res_computed, 8, res_star);
    }

    if (kdf_result != 0) {
        fprintf(stderr, "%s ERROR: Failed to compute RES*\n", LOG_TAG);
        return -1;
    }

    printf("%s SUCCESS: RES* computation complete\n", LOG_TAG);

    return 0;
}
