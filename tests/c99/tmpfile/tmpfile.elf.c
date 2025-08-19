#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    FILE *file = tmpfile();
    if(file == NULL) {
        exit(1);
    }    
    return *good;
}
