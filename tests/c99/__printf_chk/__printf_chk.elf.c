#include <stdlib.h>

// _FORTIFY_SOURCE builds emit __printf_chk(flag, fmt, ...) for printf(fmt, ...).
// Fortify is disabled for these test binaries, so call it directly. The model
// must format past the leading `flag` and return the number of chars written.
extern int __printf_chk(int flag, const char *fmt, ...);

int main() {
    char *good = (char *)(size_t)0xdead0;
    int n = __printf_chk(1, "%d", 42);  // writes "42"
    if (n != 2) {
        exit(1);
    }
    return *good;
}
