#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead;
    char buf1[8] = {
        'f', 'o', 'o', ' ',
        'f', 'o', 'o', '\0'
    };
    char buf2[4] = {
        'f', 'o', 'o', '\0'
    };
    char *str = strtok(buf1, " ");
    if(str != buf1) {
        exit(0);
    }
    str = strtok(NULL, " ");
    if(str != buf1 + 4) {
        exit(0);
    }
    str = strtok(NULL, " ");
    if(str != NULL) {
        exit(0);
    }
    
    str = strtok(buf2, " ");
    if(str != buf2) {
        exit(0);
    }
    str = strtok(NULL, " ");
    if(str != NULL) {
        exit(0);
    }
    return *good;
}
