#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    int x;

    x = atoi("42");
    if(x != 42) {
        exit(0);
    }
    x = atoi("-42");
    if(x != -42) {
        exit(0);
    }
    x = atoi("42foo");
    if(x != 42) {
        exit(0);
    }
    x = atoi("foobar");
    if(x != 0) {
        exit(0);
    }
    return *bad;
}
