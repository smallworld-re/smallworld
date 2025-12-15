#include <features.h>
#undef __GLIBC_USE_DEPRECATED_GETS
#define __GLIBC_USE_DEPRECATED_GETS 1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    char buf[16];
    
    char *res = gets(buf);
    
    if(!strcmp("foobar", res)) {
        exit(1);
    }
    return *good;
}
