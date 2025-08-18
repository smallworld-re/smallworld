#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    int res = 0;

    FILE *file = fopen("/tmp/foobar", "r");
    if(res = fclose(file)) {
        printf("Error from fclose: %d\n", res);
        exit(1);
    }

    res = fgetc(file);
    if(res != -1) {
        printf("Unexpected from fgetc: %d\n", res);
        exit(1);
    }

    return *good;
}
