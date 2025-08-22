#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    FILE *file = fopen("/tmp/foobar", "w");
    fpos_t pos;
    if(file == NULL) {
        exit(1);
    }
    if(fgetpos(file, &pos)) {
        exit(1);
    }
    if(-1 == fwrite("foobar", 6, 1, file)) {
        exit(1);
    }
    if(fsetpos(file, &pos)) {
        exit(1);
    }
    if(-1 == fwrite("bazgorp", 7, 1, file)) {
        exit(1);
    }
    return *good;
}
