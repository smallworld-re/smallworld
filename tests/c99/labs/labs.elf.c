#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    long x = labs(-2l);
    if(x != 2l) {
        exit(0);
    }
    return *bad;
}
