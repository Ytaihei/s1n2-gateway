#include "s1n2_log.h"
/**
 * @file kdf_eps.c
 * @brief 4G EPS Key Derivation Functions (3GPP TS 33.401)
 *
 * Implements:
 *   - K_ASME derivation (Annex A.2)
 *   - K_NASint / K_NASenc derivation (Annex A.7)
 *   - KeNB derivation (Annex A.3)
 *   - Convenience helper for full key hierarchy
 */
#include "kdf_eps.h"
#include "subscriber_auth.h"
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#define LOG_TAG "[s1n2_auth]"

/* Forward declaration — Milenage is in crypto/milenage.c */
extern void s1n2_milenage_f2345(const uint8_t *opc, const uint8_t *k,
                                const uint8_t *rand,
                                uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak);

/* ------------------------------------------------------------------ */
/* Generic KDF (TS 33.401 Annex A.2 common)                           */
/* ------------------------------------------------------------------ */

/**
 * @brief Generic KDF for LTE (3GPP TS 33.401 Annex A.2)
 *
 * KDF(Key, S) = HMAC-SHA-256(Key, FC || P0 || L0 || P1 || L1 || ... || Pn || Ln)
 */
static int kdf_hmac_sha256(const uint8_t *key, size_t key_len,
                           uint8_t fc,
                           const uint8_t **params, const uint16_t *param_lens,
                           int num_params,
                           uint8_t *output) {
    if (!key || !params || !param_lens || !output) {
        return -1;
    }

    uint8_t input[512];
    size_t input_len = 0;

    input[input_len++] = fc;

    for (int i = 0; i < num_params; i++) {
        if (params[i] && param_lens[i] > 0) {
            if (input_len + param_lens[i] + 2 > sizeof(input)) {
                LOG_ERROR("%s ERROR: KDF input buffer overflow\n", LOG_TAG);
                return -1;
            }
            memcpy(&input[input_len], params[i], param_lens[i]);
            input_len += param_lens[i];

            input[input_len++] = (param_lens[i] >> 8) & 0xFF;
            input[input_len++] = param_lens[i] & 0xFF;
        }
    }

    unsigned int out_len;
    if (!HMAC(EVP_sha256(), key, key_len, input, input_len, output, &out_len)) {
        LOG_ERROR("%s ERROR: HMAC-SHA-256 failed in KDF\n", LOG_TAG);
        return -1;
    }

    if (out_len != 32) {
        LOG_ERROR("%s ERROR: Unexpected HMAC output length: %u\n", LOG_TAG, out_len);
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* K_ASME derivation (TS 33.401 Annex A.2)                            */
/* ------------------------------------------------------------------ */

int s1n2_kdf_kasme(const uint8_t *ck, const uint8_t *ik,
                   const uint8_t *sqn_xor_ak, const uint8_t *plmn_id,
                   uint8_t *kasme) {
    if (!ck || !ik || !sqn_xor_ak || !plmn_id || !kasme) {

        return -1;
    }

    /* Key = CK || IK (32 bytes) */
    uint8_t key[32];
    memcpy(key, ck, 16);
    memcpy(key + 16, ik, 16);

    /* CRITICAL FIX 2025-11-16: Verify SQN^AK is not all zeros */
    bool sqn_is_zero = true;
    for (int i = 0; i < 6; i++) {
        if (sqn_xor_ak[i] != 0) {
            sqn_is_zero = false;
            break;
        }
    }
    if (sqn_is_zero) {
        LOG_WARN("%s [SQN-FIX] ⚠️  SQN^AK is all zeros! This will cause Sync Failure!\n", LOG_TAG);
        LOG_WARN("%s [SQN-FIX] ⚠️  UE will reject this as invalid SQN\n", LOG_TAG);
    } else {
        LOG_INFO("%s [SQN-FIX] ✅ SQN^AK is non-zero (correct)\n", LOG_TAG);
    }

    /* FC = 0x10 (K_ASME derivation) */
    const uint8_t fc = 0x10;

    const uint8_t *params[2] = {plmn_id, sqn_xor_ak};
    const uint16_t param_lens[2] = {3, 6};

    int ret = kdf_hmac_sha256(key, 32, fc, params, param_lens, 2, kasme);

    memset(key, 0, sizeof(key));

    return ret;
}

/* ------------------------------------------------------------------ */
/* K_NASint / K_NASenc derivation (TS 33.401 Annex A.7)               */
/* ------------------------------------------------------------------ */

int s1n2_kdf_nas_keys(const uint8_t *kasme, uint8_t algorithm_type,
                      uint8_t algorithm_id, uint8_t *key_out) {
    if (!kasme || !key_out) {
        LOG_ERROR("%s ERROR: NULL parameter in s1n2_kdf_nas_keys\n", LOG_TAG);
        return -1;
    }

    const uint8_t fc = 0x15;

    uint8_t algo_type_dist = algorithm_type;
    uint8_t algo_id = algorithm_id;

    const uint8_t *params[2] = {&algo_type_dist, &algo_id};
    const uint16_t param_lens[2] = {1, 1};

    uint8_t output[32];
    int ret = kdf_hmac_sha256(kasme, 32, fc, params, param_lens, 2, output);

    if (ret == 0) {
        /* NOTE: srsRAN UE uses second 16 bytes (offset [16]) for MAC computation */
        memcpy(key_out, output + 16, 16);

    } else {

    }

    memset(output, 0, sizeof(output));

    return ret;
}

/* ------------------------------------------------------------------ */
/* Full 4G key hierarchy helper                                       */
/* ------------------------------------------------------------------ */

int s1n2_derive_4g_nas_keys(const uint8_t *k, const uint8_t *opc,
                            const uint8_t *rand, const uint8_t *sqn_xor_ak,
                            const uint8_t *plmn_id,
                            uint8_t int_alg, uint8_t enc_alg,
                            uint8_t *k_nas_int, uint8_t *k_nas_enc) {
    if (!k || !opc || !rand || !sqn_xor_ak || !plmn_id ||
        !k_nas_int || !k_nas_enc) {
        LOG_ERROR("%s ERROR: NULL parameter in s1n2_derive_4g_nas_keys\n", LOG_TAG);
        return -1;
    }

    LOG_INFO("%s Deriving 4G NAS keys (int_alg=%u, enc_alg=%u)\n",
           LOG_TAG, int_alg, enc_alg);

    /* Step 1: Compute CK and IK using Milenage */
    uint8_t ck[16], ik[16];
    s1n2_milenage_f2345(opc, k, rand, NULL, ck, ik, NULL);

    /* Step 2: Derive K_ASME */
    uint8_t kasme[32];
    if (s1n2_kdf_kasme(ck, ik, sqn_xor_ak, plmn_id, kasme) != 0) {

        memset(ck, 0, sizeof(ck));
        memset(ik, 0, sizeof(ik));
        return -1;
    }

    /* Step 3: Derive K_NASint (algorithm type = 0x02)
     * NOTE: srsRAN uses 0x02 for integrity (opposite of 3GPP TS 33.401 which uses 0x01) */
    if (s1n2_kdf_nas_keys(kasme, 0x02, int_alg, k_nas_int) != 0) {

        memset(ck, 0, sizeof(ck));
        memset(ik, 0, sizeof(ik));
        memset(kasme, 0, sizeof(kasme));
        return -1;
    }

    /* Step 4: Derive K_NASenc (algorithm type = 0x01)
     * NOTE: srsRAN uses 0x01 for encryption (opposite of 3GPP TS 33.401 which uses 0x02) */
    if (s1n2_kdf_nas_keys(kasme, 0x01, enc_alg, k_nas_enc) != 0) {

        memset(ck, 0, sizeof(ck));
        memset(ik, 0, sizeof(ik));
        memset(kasme, 0, sizeof(kasme));
        memset(k_nas_int, 0, 16);
        return -1;
    }

    memset(ck, 0, sizeof(ck));
    memset(ik, 0, sizeof(ik));
    memset(kasme, 0, sizeof(kasme));

    LOG_INFO("%s 4G NAS keys derived successfully\n", LOG_TAG);
    return 0;
}

/* ------------------------------------------------------------------ */
/* KeNB derivation (TS 33.401 Annex A.3)                              */
/* ------------------------------------------------------------------ */

int s1n2_kdf_kenb(const uint8_t *kasme, uint32_t ul_count, uint8_t *kenb) {
    if (!kasme || !kenb) {

        return -1;
    }

    const uint8_t fc = 0x11;

    uint8_t p0[4];
    p0[0] = (ul_count >> 24) & 0xFF;
    p0[1] = (ul_count >> 16) & 0xFF;
    p0[2] = (ul_count >> 8) & 0xFF;
    p0[3] = ul_count & 0xFF;

    uint16_t p0_len = 4;

    uint8_t *params[1] = {p0};
    uint16_t param_lens[1] = {p0_len};

    LOG_INFO("%s [KDF] ========================================\n", LOG_TAG);

    LOG_INFO("%s [KDF]   NAS_COUNT = 0x%08X\n", LOG_TAG, ul_count);

    int ret = kdf_hmac_sha256(kasme, 32, fc, (const uint8_t **)params, param_lens, 1, kenb);

    if (ret != 0) {

        return -1;
    }

    LOG_INFO("%s [KDF] ========================================\n", LOG_TAG);

    return 0;
}
