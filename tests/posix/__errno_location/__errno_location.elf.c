#include <stdlib.h>

// glibc's thread-local errno accessor. The model returns a stable, writable
// per-model buffer. Confirm: writes persist and repeated calls return the same
// location.
extern int *__errno_location(void);

int main() {
    char *good = (char *)(size_t)0xdead0;
    int *e = __errno_location();
    if (e == 0) {
        exit(1);
    }
    *e = 42;
    int *e2 = __errno_location();
    if (e2 != e || *e2 != 42) {
        exit(1);
    }
    return *good;
}
