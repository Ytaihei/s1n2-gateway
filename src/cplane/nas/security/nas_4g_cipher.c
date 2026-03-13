#include "internal/nas_security.h"
#include <stdio.h>
#include <string.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

/**
 * @file security/nas_4g_cipher.c
 * @brief NAS security implementation for 4G (EPS) messages
 *
 * Implements NAS integrity protection using AES-CMAC (128-EIA2)
 * as specified in 3GPP TS 33.401.
 */

/**
 * @brief Compute 128-EIA2 MAC using AES-CMAC
 *
 * Algorithm from 3GPP TS 33.401 Annex B.2.3
 *
 * Input: COUNT (32 bits), BEARER (5 bits), DIRECTION (1 bit), MESSAGE
 * Output: MAC-I (32 bits)
 *
 * The MAC is computed over a modified input that includes COUNT, BEARER,
 * DIRECTION, and the message itself.
 */
static int compute_eia2_mac(
    const uint8_t *key,
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t *message,
    size_t msg_len,
    uint8_t *mac_out)
{
    CMAC_CTX *cmac_ctx = NULL;
    uint8_t input[8 + 2048]; // Header (8 bytes) + message
    size_t input_len;
    uint8_t cmac[16];
    size_t cmac_len;
    int ret = -1;

    if (!key || !message || !mac_out || msg_len > 2040) {
        fprintf(stderr, "[ERROR] Invalid parameters for EIA2 MAC computation\n");
        return -1;
    }

    // Build input: COUNT || BEARER || DIRECTION || 0^26 || MESSAGE
    // According to 3GPP TS 33.401 B.2.3

    // Bytes 0-3: COUNT (32 bits, big-endian)
    input[0] = (count >> 24) & 0xFF;
    input[1] = (count >> 16) & 0xFF;
    input[2] = (count >> 8) & 0xFF;
    input[3] = count & 0xFF;

    // Byte 4: BEARER (5 bits, MSB) || DIRECTION (1 bit) || 0^2
    input[4] = ((bearer & 0x1F) << 3) | ((direction & 0x01) << 2);

    // Bytes 5-7: Zero padding
    input[5] = 0x00;
    input[6] = 0x00;
    input[7] = 0x00;

    // Copy message
    memcpy(input + 8, message, msg_len);
    input_len = 8 + msg_len;

    // Debug: Print MAC calculation input
    printf("[DEBUG] EIA2 MAC Input (count=0x%08X, bearer=%u, dir=%u, msg_len=%zu):\n",
           count, bearer, direction, msg_len);
    printf("[DEBUG]   Header: %02X %02X %02X %02X %02X %02X %02X %02X\n",
           input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7]);
    printf("[DEBUG]   Message (full %zu bytes): ", msg_len);
    for (size_t i = 0; i < msg_len; i++) {
        printf("%02X ", message[i]);
        if ((i + 1) % 32 == 0 && i + 1 < msg_len) printf("\n[DEBUG]   ");
    }
    printf("\n");    // Compute CMAC using OpenSSL
    cmac_ctx = CMAC_CTX_new();
    if (!cmac_ctx) {
        fprintf(stderr, "[ERROR] Failed to create CMAC context\n");
        goto cleanup;
    }

    if (CMAC_Init(cmac_ctx, key, 16, EVP_aes_128_cbc(), NULL) != 1) {
        fprintf(stderr, "[ERROR] Failed to initialize CMAC\n");
        goto cleanup;
    }

    if (CMAC_Update(cmac_ctx, input, input_len) != 1) {
        fprintf(stderr, "[ERROR] Failed to update CMAC\n");
        goto cleanup;
    }

    if (CMAC_Final(cmac_ctx, cmac, &cmac_len) != 1) {
        fprintf(stderr, "[ERROR] Failed to finalize CMAC\n");
        goto cleanup;
    }

    // Take first 4 bytes as MAC-I
    memcpy(mac_out, cmac, 4);

    ret = 0;

cleanup:
    if (cmac_ctx) {
        CMAC_CTX_free(cmac_ctx);
    }

    return ret;
}

int s1n2_nas_compute_mac(
    s1n2_nas_integrity_alg_t algorithm,
    const uint8_t *key,
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t *message,
    size_t msg_len,
    uint8_t *mac_out)
{
    if (!key || !message || !mac_out) {
        return -1;
    }

    switch (algorithm) {
        case S1N2_NAS_EIA0:
            // NULL algorithm - no protection
            memset(mac_out, 0, 4);
            return 0;

        case S1N2_NAS_EIA2:
            // AES-CMAC based
            return compute_eia2_mac(key, count, bearer, direction, message, msg_len, mac_out);

        case S1N2_NAS_EIA1:
        case S1N2_NAS_EIA3:
            // Not implemented yet
            fprintf(stderr, "[ERROR] EIA%d not implemented\n", algorithm);
            return -1;

        default:
            fprintf(stderr, "[ERROR] Unknown integrity algorithm: %d\n", algorithm);
            return -1;
    }
}

int s1n2_compute_smc_mac(
    s1n2_nas_integrity_alg_t algorithm,
    const uint8_t *key,
    uint32_t count,
    const uint8_t *plain_nas,
    size_t plain_len,
    uint8_t *mac_out)
{
    // Security Mode Command is always downlink (direction=1)
    // Bearer ID is 0 for NAS messages
    return s1n2_nas_compute_mac(algorithm, key, count, 0, 1, plain_nas, plain_len, mac_out);
}

int s1n2_nas_encrypt(
    s1n2_nas_encryption_alg_t algorithm,
    const uint8_t *key,
    uint32_t count,
    uint8_t bearer,
    uint8_t direction,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    if (!key || !input || !output) return -1;

    switch (algorithm) {
        case S1N2_NAS_EEA0: {
            // NULL encryption
            if (input != output) memcpy(output, input, input_len);
            return 0;
        }
        case S1N2_NAS_EEA2: {
            // AES-CTR per 3GPP TS 33.401 Annex B.4
            // Counter block structure (128 bits):
            // COUNT[31:0] || BEARER[4:0] || DIRECTION[0] || 26*0 || CTR[63:0]
            AES_KEY aes_key;
            if (AES_set_encrypt_key(key, 128, &aes_key) != 0) {
                fprintf(stderr, "[ERROR] Failed to set AES key for EEA2\n");
                return -1;
            }

            uint8_t ctr_blk[16] = {0};
            // COUNT (big-endian)
            ctr_blk[0] = (uint8_t)((count >> 24) & 0xFF);
            ctr_blk[1] = (uint8_t)((count >> 16) & 0xFF);
            ctr_blk[2] = (uint8_t)((count >> 8) & 0xFF);
            ctr_blk[3] = (uint8_t)(count & 0xFF);
            // BEARER (5 bits) | DIRECTION (1 bit)
            ctr_blk[4] = (uint8_t)(((bearer & 0x1F) << 3) | ((direction & 0x01) << 2));
            // ctr_blk[5..7] remain 0 (26 zero bits across byte4 bits2..0 and bytes5..7)

            uint64_t ctr = 0; // 64-bit block counter
            size_t offset = 0;
            while (offset < input_len) {
                // Set last 8 bytes to current counter (big-endian)
                ctr_blk[8] = (uint8_t)((ctr >> 56) & 0xFF);
                ctr_blk[9] = (uint8_t)((ctr >> 48) & 0xFF);
                ctr_blk[10] = (uint8_t)((ctr >> 40) & 0xFF);
                ctr_blk[11] = (uint8_t)((ctr >> 32) & 0xFF);
                ctr_blk[12] = (uint8_t)((ctr >> 24) & 0xFF);
                ctr_blk[13] = (uint8_t)((ctr >> 16) & 0xFF);
                ctr_blk[14] = (uint8_t)((ctr >> 8) & 0xFF);
                ctr_blk[15] = (uint8_t)(ctr & 0xFF);

                uint8_t ks[16];
                AES_encrypt(ctr_blk, ks, &aes_key);

                size_t blk = (input_len - offset >= 16) ? 16 : (input_len - offset);
                for (size_t i = 0; i < blk; ++i) {
                    output[offset + i] = input[offset + i] ^ ks[i];
                }

                offset += blk;
                ctr++;
            }

            return 0;
        }
        case S1N2_NAS_EEA1:
        case S1N2_NAS_EEA3:
        default:
            fprintf(stderr, "[ERROR] EEA%d not implemented\n", algorithm);
            return -1;
    }
}
