#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[16] = { 
        'f', 'o', 'o', '\0',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1'
    };
    char *str = strncat(buf, "foobar", 15);
    buf[15] = '\0';
    if(strcmp(str, "foofoobar")) {
        exit(1);
    }
    return *bad;
}
