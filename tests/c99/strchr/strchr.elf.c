#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    if(!strchr("foobar", 'f')) {
        exit(0);
    }
    // C masks the value to unsigned char before searching, so 0x100 | 'f'
    // searches for 'f'. The previous model rejected any value > 255 and
    // returned NULL.
    if(!strchr("foobar", 0x100 + 'f')) {
        exit(0);
    }
    return *bad;
}
