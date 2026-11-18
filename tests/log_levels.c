#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "s1n2_log.h"
int main(void) {
    FILE *capture=tmpfile(); assert(capture);
    int saved=dup(STDERR_FILENO); assert(saved>=0);
    fflush(stderr); assert(dup2(fileno(capture),STDERR_FILENO)>=0);
    s1n2_log_set_level(S1N2_LOG_WARN);
    LOG_DEBUG("hidden debug"); LOG_INFO("hidden info"); LOG_WARN("visible warning\nsecond line");
    fflush(stderr); assert(dup2(saved,STDERR_FILENO)>=0); close(saved);
    rewind(capture);char text[4096]={0};assert(fread(text,1,sizeof(text)-1,capture)>0);fclose(capture);
    assert(!strstr(text,"hidden") && strstr(text,"[WARN] [log_levels.c] visible warning second line\n"));
    assert(!s1n2_log_enabled((s1n2_log_level_t)99));
    puts("PASS: log levels and single-line event format");
}
