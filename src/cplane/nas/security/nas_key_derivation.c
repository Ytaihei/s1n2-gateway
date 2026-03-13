/**
 * @file security/nas_key_derivation.c
 * @brief 4G NAS key derivation from cached authentication vectors
 *
 * Derives K_NAS_int and K_NAS_enc (4G EPS) from subscriber Ki/OPc
 * and cached RAND/AUTN/SQN^AK.  Called after Authentication Response
 * to enable NAS integrity/ciphering on the 4G side.
 *
 * @see 3GPP TS 33.401 (EPS key hierarchy)
 */
#include "internal/s1n2_converter_internal.h"

int s1n2_try_derive_4g_nas_keys(s1n2_context_t *ctx, ue_id_mapping_t *ue_map) {
    if (!ctx || !ue_map || ue_map->has_nas_keys) {
        return (ue_map && ue_map->has_nas_keys) ? 0 : -1;
    }
    if (!ctx->auth_ctx) {
        return -1;
    }
    if (!ue_map->rand_cached || !ue_map->autn_cached) {
        return -1;
    }
    if (ue_map->imsi[0] == '\0') {
        return -1;
    }

    s1n2_subscriber_keys_t *keys = s1n2_auth_get_keys(ctx->auth_ctx, ue_map->imsi);
    if (!keys || !keys->configured) {
        printf("[WARN] [NAS-KEY] Subscriber keys not found for IMSI %s\n", ue_map->imsi);
        fflush(stdout);
        return -1;
    }

    uint8_t plmn_id[3] = {0x00, 0xF1, 0x10};
    if (ue_map->plmn_id_len == 3) {
        memcpy(plmn_id, ue_map->plmn_id, 3);
    } else {
        const char *env_mcc = getenv("S1N2_MCC");
        if (!env_mcc || !*env_mcc) env_mcc = getenv("MCC");
        if (!env_mcc || !*env_mcc) env_mcc = "001";
        const char *env_mnc = getenv("S1N2_MNC");
        if (!env_mnc || !*env_mnc) env_mnc = getenv("MNC");
        if (!env_mnc || !*env_mnc) env_mnc = "01";
        s1n2_encode_plmn_from_strings(env_mcc, env_mnc, plmn_id);
    }

    uint8_t int_alg = (ue_map->selected_nas_security_alg >> 4) & 0x0F;
    uint8_t enc_alg = ue_map->selected_nas_security_alg & 0x0F;
    if (int_alg == 0) int_alg = 2;
    if (enc_alg == 0) enc_alg = 2;

    int rc = s1n2_derive_4g_nas_keys(keys->ki, keys->opc,
                                     ue_map->rand,
                                     ue_map->sqn_xor_ak,
                                     plmn_id,
                                     int_alg,
                                     enc_alg,
                                     ue_map->k_nas_int,
                                     ue_map->k_nas_enc);
    if (rc == 0) {
        ue_map->has_nas_keys = true;
        ue_map->nas_ul_count = 0;
        ue_map->nas_dl_count = 0;
        printf("[SUCCESS] [NAS-KEY] Derived 4G NAS keys for IMSI %s (int_alg=%u enc_alg=%u)\n",
               ue_map->imsi, int_alg, enc_alg);
        fflush(stdout);
    } else {
        printf("[ERROR] [NAS-KEY] Failed to derive NAS keys for IMSI %s (rc=%d)\n",
               ue_map->imsi, rc);
        fflush(stdout);
    }
    return rc;
}
