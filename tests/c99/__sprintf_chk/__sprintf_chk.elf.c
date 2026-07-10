#include <string.h>
#include <stdlib.h>

// __sprintf_chk(s, flag, slen, fmt, ...) is fortified sprintf.
extern int __sprintf_chk(char *s, int flag, size_t slen, const char *fmt, ...);

int main() {
    char *good = (char *)(size_t)0xdead0;
    char buf[16];
    int n = __sprintf_chk(buf, 1, sizeof(buf), "%x", 255);
    if (n != 2) {
        exit(1);
    }
    if (memcmp(buf, "ff", 3) != 0) {  // includes the trailing NUL
        exit(1);
    }
    return *good;
}
