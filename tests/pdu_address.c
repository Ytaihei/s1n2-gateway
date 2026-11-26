#include <assert.h>
#include <string.h>
#include "s1n2_converter.h"
#include "registration/registration_bridge.h"
#include "registration/registration.h"

int main(void) {
    ue_id_mapping_t ue={0}; ue.pdu_session_id=5;
    /* QoS rules contain a fake address IE: the parser must skip their payload. */
    uint8_t nas[]={0x7e,0,0x68,1,0,24, 0x2e,5,1,0xc2,0x11,
        0,7,0x29,5,1,192,168,100,2, 0, 0x59,0, 0x29,5,1,10,45,0,7};
    assert(sizeof(nas)==30);
    assert(s1n2_cache_pdu_address(&ue,nas,sizeof(nas))==0);
    const uint8_t ip[]={10,45,0,7};
    assert(ue.has_pdu_ipv4 && memcmp(ue.pdu_ipv4,ip,4)==0);
    uint8_t reg[]={0x7e,0,0x42,1,1}, out[512];size_t len=sizeof(out);
    assert(registration_accept_convert_5g_to_4g(reg,sizeof(reg),out,&len,&ue)==0);
    bool found=false;
    for(size_t i=0;i+6<=len;i++) if(out[i]==5 && out[i+1]==1 && !memcmp(out+i+2,ip,4)) found=true;
    assert(found);
    for(size_t n=0;n<sizeof(nas);n++) assert(s1n2_cache_pdu_address(&ue,nas,n)==-1);
    assert(memcmp(ue.pdu_ipv4,ip,4)==0);
    nas[7]=6; assert(s1n2_cache_pdu_address(&ue,nas,sizeof(nas))==-1);
    nas[7]=5; nas[25]=2; assert(s1n2_cache_pdu_address(&ue,nas,sizeof(nas))==-1);
    ue.has_pdu_ipv4=false; len=sizeof(out);
    assert(registration_accept_convert_5g_to_4g(reg,sizeof(reg),out,&len,&ue)==-1);
    puts("PASS: core-assigned IP, EPS address encoding, session mismatch and truncated input");
}
