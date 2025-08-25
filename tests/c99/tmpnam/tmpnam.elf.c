#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
        
    char buf[L_tmpnam];
    char *res = tmpnam(buf);
    if(res == NULL) {
        exit(1);
    }
    return *good;
}
