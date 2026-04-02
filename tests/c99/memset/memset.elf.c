#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[8];
    memset(buf, 'a', 8);
    for(int i = 0; i < 8; i++) {
        if(buf[i] != 'a') {
            exit(1);
        }
    }
    return *bad;
}
