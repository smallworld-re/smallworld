#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    void *buf = malloc(64);
    free(buf);
    return *bad;
}
