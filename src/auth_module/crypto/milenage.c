/**
 * @file milenage.c
 * @brief Milenage f2-f5 functions (3GPP TS 35.206)
 *
 * Implements the Milenage algorithm set for USIM authentication:
 *   - f2: RES computation
 *   - f3: CK computation
 *   - f4: IK computation
 *   - f5: AK computation
 *   - AUTS SQN decoding
 */
#include "milenage.h"
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

#define LOG_TAG "[s1n2_auth]"

/* ------------------------------------------------------------------ */
/* Milenage primitives                                                */
/* ------------------------------------------------------------------ */

static void xor_128(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    for (size_t i = 0; i < 16; i++) {
        out[i] = a[i] ^ b[i];
    }
}

static void rotate_left_128(uint8_t *out, const uint8_t *in, int bits) {
    if (bits <= 0) {
        memcpy(out, in, 16);
        return;
    }

    int shift = bits % 128;
    int byte_shift = shift / 8;
    int bit_shift = shift % 8;

    for (int i = 0; i < 16; i++) {
        uint8_t val = in[(i + byte_shift) % 16] << bit_shift;
        if (bit_shift) {
            uint8_t next = in[(i + byte_shift + 1) % 16];
            val |= (next >> (8 - bit_shift));
        }
        out[i] = val;
    }
}

/* ------------------------------------------------------------------ */
/* f2-f5 (TS 35.206)                                                  */
/* ------------------------------------------------------------------ */

void s1n2_milenage_f2345(const uint8_t *opc, const uint8_t *k,
                         const uint8_t *rand,
                         uint8_t *res, uint8_t *ck, uint8_t *ik, uint8_t *ak) {
    if (!opc || !k || !rand) {
        fprintf(stderr, "%s ERROR: NULL parameter in milenage_f2345\n", LOG_TAG);
        return;
    }

    AES_KEY aes_key;
    if (AES_set_encrypt_key(k, 128, &aes_key) != 0) {
        fprintf(stderr, "%s ERROR: Failed to initialise AES key for Milenage\n", LOG_TAG);
        return;
    }

    static const uint8_t c2[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    static const uint8_t c3[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    static const uint8_t c4[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};
    static const uint8_t c5[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08};

    uint8_t rand_xor_opc[16];
    uint8_t temp[16];
    uint8_t temp_xor_opc[16];
    uint8_t rotated[16];
    uint8_t out[16];

    xor_128(rand_xor_opc, rand, opc);
    AES_encrypt(rand_xor_opc, temp, &aes_key);
    xor_128(temp_xor_opc, temp, opc);

    if (res) {
        rotate_left_128(rotated, temp_xor_opc, 0);
        for (int i = 0; i < 16; i++) rotated[i] ^= c2[i];
        AES_encrypt(rotated, out, &aes_key);
        xor_128(out, out, opc);
        memcpy(res, out + 8, 8);
    }

    if (ck) {
        rotate_left_128(rotated, temp_xor_opc, 32);
        for (int i = 0; i < 16; i++) rotated[i] ^= c3[i];
        AES_encrypt(rotated, out, &aes_key);
        xor_128(out, out, opc);
        memcpy(ck, out, 16);
    }

    if (ik) {
        rotate_left_128(rotated, temp_xor_opc, 64);
        for (int i = 0; i < 16; i++) rotated[i] ^= c4[i];
        AES_encrypt(rotated, out, &aes_key);
        xor_128(out, out, opc);
        memcpy(ik, out, 16);
    }

    if (ak) {
        rotate_left_128(rotated, temp_xor_opc, 96);
        for (int i = 0; i < 16; i++) rotated[i] ^= c5[i];
        AES_encrypt(rotated, out, &aes_key);
        xor_128(out, out, opc);
        memcpy(ak, out, 6);
    }
}

/* ------------------------------------------------------------------ */
/* AUTS SQN decoding (TS 33.102)                                      */
/* ------------------------------------------------------------------ */

/**
 * @brief Decode UE's expected SQN from AUTS (Authentication Failure Token)
 *
 * AUTS structure (3GPP TS 33.102):
 *   AUTS = SQN_MS ⊕ AK || MAC-S
 *          (6 bytes)    (8 bytes)
 *
 * This function computes AK using Milenage f5, then XORs it with SQN_MS⊕AK
 * to recover the UE's expected SQN value.
 */
int s1n2_decode_auts_sqn(const uint8_t *opc, const uint8_t *k,
                         const uint8_t *rand, const uint8_t *auts,
                         uint8_t *sqn_ms) {
    if (!opc || !k || !rand || !auts || !sqn_ms) {
        fprintf(stderr, "%s ERROR: NULL parameter in decode_auts_sqn\n", LOG_TAG);
        return -1;
    }

    /* Extract SQN_MS ⊕ AK from AUTS (first 6 bytes) */
    uint8_t sqn_ms_xor_ak[6];
    memcpy(sqn_ms_xor_ak, auts, 6);

    /* Compute AK using Milenage f5 */
    uint8_t ak[6];
    s1n2_milenage_f2345(opc, k, rand, NULL, NULL, NULL, ak);

    /* Recover SQN_MS: SQN_MS = (SQN_MS ⊕ AK) ⊕ AK */
    for (int i = 0; i < 6; i++) {
        sqn_ms[i] = sqn_ms_xor_ak[i] ^ ak[i];
    }

    return 0;
}
