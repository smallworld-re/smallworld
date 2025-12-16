#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    FILE *file = fopen("/tmp/foobar", "w");
    fpos_t pos;
    if(file == NULL) {
        exit(1);
    }
    if(-1 == fwrite("foobar", 6, 1, file)) {
        exit(1);
    }
    // fpos_t is opaque;
    // will test this more extensively with fsetpos
    if(fgetpos(file, &pos)) {
        exit(1);
    }
    return *good;
}
