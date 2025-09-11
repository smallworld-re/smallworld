#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    char *buf = (char *)malloc(64);
    buf[64] = 'A';
    free(buf);
    return *bad;
}
