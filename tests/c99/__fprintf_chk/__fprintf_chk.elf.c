#include <stdio.h>
#include <stdlib.h>

// __fprintf_chk(fp, flag, fmt, ...) is the fortified fprintf(fp, fmt, ...).
extern int __fprintf_chk(FILE *fp, int flag, const char *fmt, ...);

int main() {
    char *good = (char *)(size_t)0xdead0;
    int n = __fprintf_chk(stderr, 1, "%s", "abc");  // writes "abc"
    if (n != 3) {
        exit(1);
    }
    return *good;
}
