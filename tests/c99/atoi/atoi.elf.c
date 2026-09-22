#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
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
    // A '-' after the first character terminates the number; it is not a
    // sign. Real atoi("12-3") == 12 and atoi("5-") == 5. The previous model
    // kept the interior dash and crashed in int("12-3").
    x = atoi("12-3");
    if(x != 12) {
        exit(0);
    }
    x = atoi("5-");
    if(x != 5) {
        exit(0);
    }
    return *bad;
}
