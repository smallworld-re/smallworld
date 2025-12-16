#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    char *buf = calloc(6, 1);
    for(int i = 0; i < 6; i++) {
        if(buf[i] != 0) {
            exit(0);
        }
    }
    buf[0] = 'f';
    return *bad;
}
