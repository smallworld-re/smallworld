#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    char *data = NULL;
    // Expect return non-NULL
    if(!(data = memchr("foobar", 'o', 4))) {
        puts("Expected non-NULL, got NULL");
        exit(1);
    }
    // Expect return NULL
    if(memchr("bazqux", 'o', 4)) {
        puts("Expected NULL, got non-NULL");
        exit(1);
    }
    // C masks the value to unsigned char before searching, so memchr(p, -1, n)
    // looks for the byte 0xFF. The previous model rejected any value outside
    // 0..255 and returned NULL. needle is a stack local (no globals: MIPS would
    // address a global GP-relative, which the harness does not set up).
    char needle[3] = {0x41, (char)0xFF, 0x42};
    if(!(data = memchr(needle, -1, sizeof(needle)))) {
        puts("Expected non-NULL for -1 (0xFF), got NULL");
        exit(1);
    }
    // Test passed
    return *bad;
}
