#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    long long x = llabs(-2ll);
    if(x != 2ll) {
        exit(0);
    }
    return *bad;
}
