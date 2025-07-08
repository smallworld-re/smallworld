#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    char buf[6];
    char *str = memmove(buf, argv[1], 6);
    if(str != buf) {
        return *bad;
    }
    if(memcmp(buf, "foobar", 6)) {
        return *bad;
    }
    exit(0);
}
