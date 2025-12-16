#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    int x = getchar();
    if(x != 'f') {
        printf("Got %02x\n", x);
        exit(1);
    }
    return *good;
}
