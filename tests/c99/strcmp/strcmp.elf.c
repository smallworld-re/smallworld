#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    if(!strcmp(argv[1], "foobar")) {
        exit(0);
    }
    return *bad;
}
