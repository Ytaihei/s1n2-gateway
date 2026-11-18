#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "s1n2_converter.h"
#include "subscriber_auth.h"
#include "security/security.h"

int main(void) {
    s1n2_context_t *ctx = calloc(1, sizeof(*ctx));
    s1n2_auth_context_t auth = {0};
    assert(ctx);
    ctx->auth_ctx = &auth;
    auth.enabled = true;
    auth.subscriber_count = 1;
    auth.subscribers[0].configured = true;
    /* Synthetic test identity and all-zero fixture keys; no deployment data. */
    strcpy(auth.subscribers[0].imsi, "001010000000001");
    const struct { uint8_t selection, integrity, encryption; } cases[] = {
        {0x02, 2, 0}, {0x20, 0, 2}, {0x22, 2, 2}, {0x00, 0, 0}, {0x12, 2, 1}
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        ue_id_mapping_t ue = {0};
        strcpy(ue.imsi, auth.subscribers[0].imsi);
        ue.rand_cached = ue.autn_cached = ue.has_security_mode = true;
        ue.selected_nas_security_alg = cases[i].selection;
        const uint8_t plmn[] = {0,0xf1,0x10};
        memcpy(ue.plmn_id, plmn, 3); ue.plmn_id_len = 3;
        uint8_t expected_int[16], expected_enc[16];
        assert(s1n2_derive_4g_nas_keys(auth.subscribers[0].ki, auth.subscribers[0].opc,
            ue.rand, ue.sqn_xor_ak, plmn, cases[i].integrity, cases[i].encryption,
            expected_int, expected_enc) == 0);
        assert(s1n2_try_derive_4g_nas_keys(ctx, &ue) == 0);
        assert(ue.has_nas_keys);
        assert(memcmp(ue.k_nas_int, expected_int, 16) == 0);
        assert(memcmp(ue.k_nas_enc, expected_enc, 16) == 0);

        /* Recover 5G selection from EPS selection when the 5G cache is absent. */
        ue.has_nas_keys = false;
        uint8_t complete[] = {7,0x5e}, output[1024];
        size_t length = sizeof(output);
        assert(smc_complete_convert_4g_to_5g(complete, sizeof(complete), 7, 0x5e,
                    2, output, &length, ctx, &ue) == 0);
        assert(ue.has_selected_alg_5g);
        assert(ue.selected_alg_5g == cases[i].selection);
    }
    free(ctx);
    puts("PASS: NAS key selection and SMC fallback (5 algorithm combinations)");
    return 0;
}
