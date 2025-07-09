#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
    int res = 0;
    res = strspn("foobar", "fobar");
    if(res != 6) {
        exit(0);
    }
    res = strspn("bazqux", "f");
    if(res != 0) {
        exit(0);
    }
    res = strspn("barfoo", "fbar");
    if(res != 4) {
        exit(0);
    }
    res = strspn("foobar", "");
    if(res != 0) {
        exit(0);
    }
    return *good;
}
