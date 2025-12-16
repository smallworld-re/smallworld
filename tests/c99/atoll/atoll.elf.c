#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    long long x;

    x = atoll("42");
    if(x != 42ll) {
        exit(0);
    }
    x = atoll("-42");
    if(x != -42ll) {
        exit(0);
    }
    x = atoll("42foo");
    if(x != 42ll) {
        exit(0);
    }
    x = atoll("foobar");
    if(x != 0ll) {
        exit(0);
    }
    return *bad;
}
