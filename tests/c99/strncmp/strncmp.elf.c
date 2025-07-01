#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    if(!strncmp(argv[1], "foobar", 6)) {
        exit(0);
    }
    return *bad;
}
