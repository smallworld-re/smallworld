#include <stddef.h>
#include <stdlib.h>

int foobar(void) {
    int *foo = (int *)(size_t)0xc001;
    *foo = 0xd00d;
    return *foo;
}

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    if(foobar() != 0xd00d) {
        exit(1);
    } 
    return *good;
}
