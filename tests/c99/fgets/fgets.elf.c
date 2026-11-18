#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    char buf[16];

    // The single line of input ("foobar\n") is consumed by the first read,
    // which must return the buffer (non-NULL).
    char *res = fgets(buf, 15, stdin);
    if (res == NULL) {
        exit(1);
    }

    // At end-of-file with no characters read, fgets must return NULL (SW-187),
    // so that `while (fgets(...))` loops terminate.
    if (fgets(buf, 15, stdin) != NULL) {
        exit(1);
    }
    return *good;
}
