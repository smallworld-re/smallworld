#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    char buf[16];
    
    size_t n = fread(buf, 15, 1, stdin);
    buf[n] = '\0';
    
    if(!strcmp("foobar", buf)) {
        exit(1);
    }
    return *good;
}
