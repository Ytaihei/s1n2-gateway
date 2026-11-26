#include "s1n2_log.h"
/**
 * @file subscriber_db.c
 * @brief Subscriber database management
 *
 * Subscriber registration, lookup, and validation functions.
 */
#define _GNU_SOURCE
#include "auth_config.h"
#include "subscriber_auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/aes.h>

#define LOG_TAG "[s1n2_auth]"

/* ------------------------------------------------------------------ */
/* IMSI validation                                                    */
/* ------------------------------------------------------------------ */

static bool s1n2_auth_is_valid_imsi(const char *imsi) {
    if (!imsi) {
        return false;
    }

    size_t len = strlen(imsi);
    if (len < 5 || len > 15) {
        return false;
    }

    for (size_t i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)imsi[i])) {
            return false;
        }
    }

    return true;
}

/* ------------------------------------------------------------------ */
/* OPc computation from OP                                            */
/* ------------------------------------------------------------------ */

static int compute_opc_from_op(const uint8_t *ki, const uint8_t *op, uint8_t *opc) {
    if (!ki || !op || !opc) {
        LOG_ERROR("%s ERROR: NULL parameter in compute_opc_from_op\n", LOG_TAG);
        return -1;
    }

    AES_KEY aes_key;
    if (AES_set_encrypt_key(ki, 128, &aes_key) != 0) {

        return -1;
    }

    uint8_t temp[16];
    AES_encrypt(op, temp, &aes_key);
    for (int i = 0; i < 16; ++i) {
        opc[i] = temp[i] ^ op[i];
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Subscriber management                                              */
/* ------------------------------------------------------------------ */

static s1n2_subscriber_keys_t* s1n2_auth_get_or_create_subscriber(s1n2_auth_context_t *auth_ctx,
                                                                   const char *imsi,
                                                                   bool *created) {
    if (!auth_ctx || !imsi) {
        return NULL;
    }

    for (int i = 0; i < auth_ctx->subscriber_count; ++i) {
        if (strcmp(auth_ctx->subscribers[i].imsi, imsi) == 0) {
            if (created) {
                *created = false;
            }
            return &auth_ctx->subscribers[i];
        }
    }

    if (auth_ctx->subscriber_count >= (int)(sizeof(auth_ctx->subscribers) / sizeof(auth_ctx->subscribers[0]))) {

        return NULL;
    }

    int index = auth_ctx->subscriber_count++;
    memset(&auth_ctx->subscribers[index], 0, sizeof(s1n2_subscriber_keys_t));
    strncpy(auth_ctx->subscribers[index].imsi, imsi, sizeof(auth_ctx->subscribers[index].imsi) - 1);
    auth_ctx->subscribers[index].imsi[sizeof(auth_ctx->subscribers[index].imsi) - 1] = '\0';

    if (created) {
        *created = true;
    }

    return &auth_ctx->subscribers[index];
}

int s1n2_auth_register_subscriber(s1n2_auth_context_t *auth_ctx,
                                  const char *imsi,
                                  const char *ki_hex,
                                  const char *opc_hex,
                                  const char *op_hex,
                                  const char *source_label) {
    if (!auth_ctx || !imsi || !ki_hex) {
        return 0;
    }

    if (!s1n2_auth_is_valid_imsi(imsi)) {

        return 0;
    }

    uint8_t ki[16];
    if (s1n2_auth_hex_to_bytes(ki_hex, ki, sizeof(ki)) != 0) {

        return 0;
    }

    uint8_t opc[16];
    bool opc_available = false;

    if (opc_hex && *opc_hex) {
        if (s1n2_auth_hex_to_bytes(opc_hex, opc, sizeof(opc)) == 0) {
            opc_available = true;
        } else {

            return 0;
        }
    }

    if (!opc_available) {
        if (!op_hex || !*op_hex) {

            return 0;
        }

        uint8_t op[16];
        if (s1n2_auth_hex_to_bytes(op_hex, op, sizeof(op)) != 0) {

            return 0;
        }

        if (compute_opc_from_op(ki, op, opc) != 0) {

            return 0;
        }
        opc_available = true;
    }

    bool created = false;
    s1n2_subscriber_keys_t *subscriber = s1n2_auth_get_or_create_subscriber(auth_ctx, imsi, &created);
    if (!subscriber) {
        return 0;
    }

    memcpy(subscriber->ki, ki, sizeof(ki));
    memcpy(subscriber->opc, opc, sizeof(opc));
    subscriber->configured = true;

    LOG_DEBUG("Subscriber credentials %s", created ? "added" : "updated");

    return 1;
}

/* ------------------------------------------------------------------ */
/* Key lookup                                                         */
/* ------------------------------------------------------------------ */

s1n2_subscriber_keys_t* s1n2_auth_get_keys(s1n2_auth_context_t *auth_ctx, const char *imsi) {
    if (!auth_ctx || !imsi) {
        return NULL;
    }

    for (int i = 0; i < auth_ctx->subscriber_count; i++) {
        if (strcmp(auth_ctx->subscribers[i].imsi, imsi) == 0) {
            if (auth_ctx->audit_logging) {
                LOG_DEBUG("Subscriber credential lookup succeeded");
            }
            return &auth_ctx->subscribers[i];
        }
    }

    return NULL;
}
