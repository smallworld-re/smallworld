#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    FILE *file = fopen("/tmp/foobar", "w");
    if(file == NULL) {
        exit(1);
    }
    if(-1 == fwrite("foobar", 6, 1, file)) {
        exit(1);
    }
    // fseek returns 0 on success, not the resulting offset. Seek to a
    // non-zero position so the two differ (the old model returned 3).
    if(fseek(file, 3, SEEK_SET) != 0) {
        exit(1);
    }
    if(-1 == fwrite("bazgorp", 7, 1, file)) {
        exit(1);
    }
    // fseek on a non-seekable stream returns -1; the old model let the
    // FDIOUnsupported exception escape and aborted emulation.
    if(fseek(stdout, 0, SEEK_SET) != -1) {
        exit(1);
    }
    return *good;
}
