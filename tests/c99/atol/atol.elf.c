#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    long x;

    x = atol("42");
    if(x != 42l) {
        exit(0);
    }
    x = atol("-42l");
    if(x != -42l) {
        exit(0);
    }
    x = atol("42foo");
    if(x != 42l) {
        exit(0);
    }
    x = atol("foobar");
    if(x != 0l) {
        exit(0);
    }
    return *bad;
}
