#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead0;

    // In the C/POSIX locale strcoll orders bytewise, exactly like strcmp; only
    // the sign of the result is defined. This is a no-regression guard: the
    // hardened model (pure bytewise compare, no host locale) must agree with
    // the C-locale answer.
    if (strcoll("abc", "abc") != 0) {
        exit(0);
    }
    if (strcoll("abc", "abd") >= 0) {
        exit(0);
    }
    if (strcoll("b", "a") <= 0) {
        exit(0);
    }
    return *good;
}
