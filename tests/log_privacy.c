#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "subscriber_auth.h"
#include "s1n2_log.h"
#include "internal/nas_module_common.h"

static void absent(const char *log, const uint8_t *bytes, size_t n) {
    char hex[129]={0}, spaced[193]={0};
    assert(n<=64);
    for(size_t i=0;i<n;i++) {
        snprintf(hex+2*i,3,"%02x",bytes[i]);
        snprintf(spaced+3*i,4,"%02x ",bytes[i]);
    }
    assert(!strstr(log,hex) && !strstr(log,spaced));
}
int main(void) {
    uint8_t k[16], opc[16], rand[16], sqn[6], integrity[16], encryption[16];
    for(size_t i=0;i<16;i++){k[i]=0xa0+i;opc[i]=0xb0+i;rand[i]=0xc0+i;}
    memset(sqn,0xdd,sizeof(sqn));
    const uint8_t plmn[]={0,0xf1,0x10};
    FILE *capture=tmpfile();assert(capture);
    int saved=dup(STDERR_FILENO);assert(saved>=0);
    fflush(stderr);assert(dup2(fileno(capture),STDERR_FILENO)>=0);
    s1n2_log_set_level(S1N2_LOG_TRACE);
    assert(s1n2_derive_4g_nas_keys(k,opc,rand,sqn,plmn,2,2,integrity,encryption)==0);
    s1n2_dump_hex("NAS",k,sizeof(k));
    fflush(stderr);assert(dup2(saved,STDERR_FILENO)>=0);close(saved);
    rewind(capture);char log[32768]={0};assert(fread(log,1,sizeof(log)-1,capture)>0);fclose(capture);
    for(size_t i=0;log[i];i++)log[i]=(char)tolower((unsigned char)log[i]);
    absent(log,k,16);absent(log,opc,16);absent(log,rand,16);
    absent(log,integrity,16);absent(log,encryption,16);
    puts("PASS: TRACE logs omit input keys, RAND, derived NAS keys and raw payloads");
}
