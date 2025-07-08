#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
    int res = 0;
    res = strcspn("foobar", "fo");
    if(res != 0) {
        exit(0);
    }
    res = strcspn("bazqux", "foo");
    if(res != 6) {
        exit(0);
    }
    res = strcspn("barfoo", "f");
    if(res != 3) {
        exit(0);
    }
    return *good;
}
