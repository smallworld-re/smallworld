#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;

    if(remove("/tmp/foobar")) {
        exit(1);
    }
    if(!remove("/tmp/bazgorp")) {
        exit(1);
    }
    return *good;
}
