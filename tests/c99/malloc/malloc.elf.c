#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    char *buf = malloc(6);
    buf[0] = 'f';
    return *bad;
}
