#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    if(fflush(stdout)) {
        exit(1);
    }
    if(fflush(NULL)) {
        exit(1);
    }
    return *good;
}
