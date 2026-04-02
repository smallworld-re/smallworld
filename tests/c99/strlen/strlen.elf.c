#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    if(strlen("foobar") != 6) {
        exit(1);
    }
    return *bad;
}
