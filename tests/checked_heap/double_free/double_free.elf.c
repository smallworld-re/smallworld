#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    void *buf = malloc(64);
    free(buf);
    free(buf);
    return *bad;
}
