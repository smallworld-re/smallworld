#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    char buf[8];
    size_t len = strlen(argv[1]) + 1;
    char *str = strncpy(buf, argv[1], 8);
    str[7] = '\0';
    if(str != buf) {
        return *bad;
    }
    if(strcmp(str, argv[1])) {
        return *bad;
    } 
    if(len < 8) {
        for(size_t i = len; i < 8; i++) {
            if(str[i] != '\0') {
                return *bad;
            }
        }   
    }
    exit(0);
}
