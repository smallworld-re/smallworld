#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    
    rename("/tmp/bazgorp", "/tmp/foobar");
    
    FILE *file = fopen("/tmp/foobar", "w");
    if(file == NULL) {
        exit(1);
    }
    return *good;
}
