#include <string.h>
#include <stdlib.h>

// realloc(NULL, ...) gets rewritten to malloc(...) by GCC.
// I insist that it doesn't.
void *(*my_realloc)(void *, size_t) = realloc;

int main() {
    char *good = (char *)(size_t)0xdead;
    char *buf = my_realloc(NULL, 64);
    buf[63] = 'f';
    buf = my_realloc(buf, 128);
    if(buf[63] == 'f') {
        return *good;
    }
    exit(1);
}
