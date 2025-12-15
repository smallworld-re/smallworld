#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    int res = 0;

    FILE *file = fopen("/tmp/foobar", "r");
    if(res = fclose(file)) {
        exit(1);
    }

    res = fgetc(file);
    if(res != -1) {
        exit(1);
    }

    return *good;
}
