#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char buf[] = { 
        'f', 'o', 'o', '\0',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1'
    };
    char *str = strcat(buf, "foobar");
    if(strcmp(str, "foofoobar")) {
        exit(1); 
    }
    return *bad;
}
