#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    char buf[8];
    char *str = strcpy(buf, argv[1]);
    str[6] = '\0';
    if(str != buf) {
        return *bad;
    }
    if(strcmp(str, argv[1])) {
        return *bad;
    }
    exit(0);
}
