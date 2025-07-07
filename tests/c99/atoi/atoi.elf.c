#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    int x;

    x = atoi("42");
    if(x != 42) {
        return *bad;
    }
    x = atoi("-42");
    if(x != -42) {
        return *bad;
    }
    x = atoi("42foo");
    if(x != 42) {
        return *bad;
    }
    x = atoi("foobar");
    if(x != 0) {
        return *bad;
    }
    exit(0);
}
