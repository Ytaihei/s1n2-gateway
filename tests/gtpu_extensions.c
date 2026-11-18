#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "gtp_header.h"
#include "gtp_tunnel.h"

int main(void) {
    /* Sequence + PDCP number + a second extension, then four payload bytes. */
    uint8_t p[]={0x36,0xff,0,16,0,0,0,1,0x12,0x34,0,0xc0,
                 1,0,7,0x85,1,0,9,0,0x45,0,0,4};
    size_t offset;
    assert(s1n2_gtpu_payload_offset(p,sizeof(p),&offset)==0 && offset==20);
    assert(gtp_tunnel_init()==0);
    assert(gtp_tunnel_add_mapping_explicit(1,0,2152,0,2152,0x500,1,5,9)==0x500);
    uint8_t *output=NULL; size_t len=0;
    assert(gtp_tunnel_process_s1u_to_n3(p,sizeof(p),&output,&len)==0);
    assert(len==20 && output[11]==0x85 && output[13]==0x10);
    assert(memcmp(output+16,p+20,4)==0);
    free(output);
    for(size_t n=0;n<sizeof(p);n++) assert(s1n2_gtpu_payload_offset(p,n,&offset)==-1);
    p[12]=0; assert(s1n2_gtpu_payload_offset(p,sizeof(p),&offset)==-1);
    p[12]=8; assert(s1n2_gtpu_payload_offset(p,sizeof(p),&offset)==-1);
    p[12]=1; p[19]=0x85; assert(s1n2_gtpu_payload_offset(p,sizeof(p),&offset)==-1);
    p[19]=0; p[3]=17; assert(s1n2_gtpu_payload_offset(p,sizeof(p),&offset)==-1);
    uint8_t optional[]={0x32,0xff,0,8,0,0,0,1,0,1,0,0,0x45,0,0,4};
    assert(s1n2_gtpu_payload_offset(optional,sizeof(optional),&offset)==0 && offset==12);
    puts("PASS: chained GTP-U extensions, optional sequence and malformed lengths");
}
