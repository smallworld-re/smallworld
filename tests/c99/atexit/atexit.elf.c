#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    void *notnull = (void *)(size_t)0xc001;
    if(atexit(notnull)) {
        exit(0);
    }
    return *bad;
}
