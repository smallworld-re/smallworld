#include <string.h>
#include <stdlib.h>


int main() {
    char *good = (char *)(size_t)0xdead0;
    char *buf = realloc(NULL, 64);
    buf[63] = 'f';
    buf = realloc(buf, 128);
    if(buf[63] == 'f') {
        return *good;
    }
    exit(1);
}
