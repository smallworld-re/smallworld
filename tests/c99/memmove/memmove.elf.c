#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[6];
    char *str = memmove(buf, "foobar", 6);
    if(str != buf) {
        exit(1);
    }
    if(memcmp(buf, "foobar", 6)) {
        exit(1);
    }
    return *bad;
}
