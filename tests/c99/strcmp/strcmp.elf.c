#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[] = {
        'f', 'o', 'o', 'b', 'a', 'r', '\0',
        'b', 'a', 'z', 'q', 'u', 'x', '\0'
    };
    if(strcmp(buf, "foobar")) {
        exit(1);
    }
    return *bad;
}
