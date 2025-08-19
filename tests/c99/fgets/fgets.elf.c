#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    char buf[16];
    
    char *res = fgets(buf, 15, stdin);
    
    if(!strcmp("foobar", res)) {
        exit(1);
    }
    return *good;
}
