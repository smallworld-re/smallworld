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
    // Test passed
    return *bad;
}
