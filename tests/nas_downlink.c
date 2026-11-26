#include <assert.h>
#include <string.h>
#include "s1n2_converter.h"
#include "internal/nas_security.h"
#include "security/security.h"

static void protect(ue_id_mapping_t *ue, int encryption, uint32_t count, uint8_t packet[11]) {
    const uint8_t plain[] = {0x7e,0,0x42,1};
    packet[0]=0x7e; packet[1]=2; packet[6]=(uint8_t)count;
    assert(s1n2_nas_encrypt((s1n2_nas_encryption_alg_t)encryption,
        ue->k_nas_enc_5g, count, 1, 1, plain, sizeof(plain), packet+7) == 0);
    assert(s1n2_nas_compute_mac(S1N2_NAS_EIA2, ue->k_nas_int_5g,
        count, 1, 1, packet+6, 5, packet+2) == 0);
}

int main(void) {
    for (int encryption=0; encryption<=2; encryption+=2) {
        ue_id_mapping_t ue={0};
        ue.has_5g_nas_keys=ue.has_selected_alg_5g=true;
        ue.selected_alg_5g=(encryption<<4)|2;
        for (uint32_t count=1; count<520; count++) {
            uint8_t packet[11], buffer[32], mac[4], seq;
            const uint8_t *decoded=NULL;
            size_t decoded_len=0;
            bool has_mac;
            protect(&ue,encryption,count,packet);
            packet[2]^=1;
            assert(nas_5g_security_unwrap(packet,sizeof(packet),&ue,&decoded,
                &decoded_len,buffer,sizeof(buffer),mac,&has_mac,&seq)==-1);
            assert(ue.nas_dl_count_5g==count-1);
            packet[2]^=1;
            assert(nas_5g_security_unwrap(packet,sizeof(packet),&ue,&decoded,
                &decoded_len,buffer,1,mac,&has_mac,&seq)==-1);
            assert(ue.nas_dl_count_5g==count-1);
            assert(nas_5g_security_unwrap(packet,sizeof(packet),&ue,&decoded,
                &decoded_len,buffer,sizeof(buffer),mac,&has_mac,&seq)==0);
            const uint8_t expected[]={0x7e,0,0x42,1};
            assert(has_mac && seq==(uint8_t)count && decoded_len==4);
            assert(memcmp(decoded,expected,4)==0);
            assert(ue.nas_dl_count_5g==count);
            assert(nas_5g_security_unwrap(packet,sizeof(packet),&ue,&decoded,
                &decoded_len,buffer,sizeof(buffer),mac,&has_mac,&seq)==-1);
        }
    }
    puts("PASS: 5G NAS NEA0/NEA2, 2 COUNT rollovers, bad MAC/replay and failure-state preservation");
}
