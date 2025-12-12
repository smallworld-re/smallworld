#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    char buf[7];
    FILE *file = fopen("/tmp/foobar", "w+");
    if(file == NULL) {
        exit(1);
    }
    if(-1 == fread(buf, 7, 1, file)) {
        exit(1);
    }
    if(!feof(file)) {
        exit(1);
    }
    return *good;
}
