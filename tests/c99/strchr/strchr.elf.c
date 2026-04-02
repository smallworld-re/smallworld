#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    if(!strchr("foobar", 'f')) {
        exit(0);
    }
    return *bad;
}
