#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    if(-1 == putchar('f')) {
        exit(1);
    }
    return *good;
}
