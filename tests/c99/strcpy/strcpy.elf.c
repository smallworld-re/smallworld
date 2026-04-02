#include <stdlib.h>
#include <string.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[8];
    char *str = strcpy(buf, "foobar");
    str[6] = '\0';
    if(str != buf) {
        exit(1);
    }
    if(strcmp(str, "foobar")) {
        exit(1);
    }
    return *bad;
}
