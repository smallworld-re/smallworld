#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    FILE *file = fopen("/tmp/foobar", "w");
    if(file == NULL) {
        exit(1);
    }
    if(-1 == fwrite("foobar", 6, 1, file)) {
        exit(1);
    }
    rewind(file);
    if(-1 == fwrite("bazgorp", 7, 1, file)) {
        exit(1);
    }
    return *good;
}
