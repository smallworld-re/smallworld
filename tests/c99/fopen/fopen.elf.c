#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;

    FILE *file = NULL;

    file = fopen("/tmp/foobar", "r");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "rb");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "r+");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "r+b");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "w");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "wb");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "w+");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "a+b");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "a");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "ab");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "a+");
    if(file == NULL) {
        exit(1);
    }

    file = fopen("/tmp/foobar", "a+b");
    if(file == NULL) {
        exit(1);
    }
    
    file = fopen("/tmp/foobar", "br");
    if(file != NULL) {
        exit(1);
    }

    return *good;
}
