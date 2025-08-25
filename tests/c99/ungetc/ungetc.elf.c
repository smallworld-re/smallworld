#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    char buf[7];
    char old = '\0';
    FILE *file = fopen("/tmp/foobar", "w+");
    if(file == NULL) {
        exit(1);
    }
    if(-1 == fread(buf, 7, 1, file)) {
        exit(1);
    }
    old = buf[0];
    ungetc(old, file);
    if(-1 == fread(buf, 1, 1, file)) {
        exit(1);
    }
    if(buf[0] != old) {
        exit(1);
    }
    return *good;
}
