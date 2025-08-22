#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    char buf[8];
    memset(buf, 'a', 8);
    for(int i = 0; i < 8; i++) {
        if(buf[i] != 'a') {
            return *bad;
        }
    }
    exit(0);
}
