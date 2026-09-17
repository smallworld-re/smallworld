#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead0;
    char buf[16];

    // C-locale strxfrm is the identity transform: it returns the transformed
    // length (== strlen(src)) and writes at most n bytes to dst, always
    // NUL-terminated. The old model returned strnlen(src, n) and wrote the
    // transform with no NUL and no bound on n. buf is a stack local (no
    // globals: MIPS would address a global GP-relative, which the harness
    // does not set up).

    // Full transform fits: returns 5, writes "hello\0".
    memset(buf, 0x7f, sizeof(buf));
    if (strxfrm(buf, "hello", sizeof(buf)) != 5) {
        exit(0);
    }
    if (memcmp(buf, "hello\0", 6) != 0) {   // old model wrote no NUL
        exit(0);
    }

    // n smaller than the source: the return is the FULL length (6), and at
    // most n bytes are written, NUL-terminated; buf[3] must be untouched.
    memset(buf, 0x7f, sizeof(buf));
    if (strxfrm(buf, "abcdef", 3) != 6) {   // old model returned 3
        exit(0);
    }
    if (buf[0] != 'a' || buf[1] != 'b' || buf[2] != '\0' || buf[3] != 0x7f) {
        exit(0);
    }

    // n == 0 with a NULL dst: return the length, write nothing.
    if (strxfrm(NULL, "xyz", 0) != 3) {
        exit(0);
    }

    return *good;
}
