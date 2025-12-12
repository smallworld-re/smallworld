#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    if(-1 == putchar('f')) {
        exit(1);
    }
    return *good;
}
