#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *bad = (char *)(size_t)0xdead;
    // Stops the damned thing from calling memset
    char buf[16] = { 
        'f', 'o', 'o', '\0',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1',
        '\0', '\1', '\0', '\1'
    };
    char *str = strncat(buf, argv[1], 15);
    buf[15] = '\0';
    if(!strcmp(str, "foofoobar")) {
        exit(0);
    }
    return *bad;
}
