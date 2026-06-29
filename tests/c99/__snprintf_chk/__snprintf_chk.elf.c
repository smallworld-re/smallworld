#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// __snprintf_chk(s, maxlen, flag, slen, fmt, ...) is fortified snprintf. The
// model must format past the `flag`/`slen` args into the buffer and return the
// length (excluding the NUL). Self-checks the produced bytes.
extern int __snprintf_chk(char *s, size_t maxlen, int flag, size_t slen,
                          const char *fmt, ...);

int main() {
    char *good = (char *)(size_t)0xdead0;
    char buf[16];
    int n = __snprintf_chk(buf, sizeof(buf), 1, sizeof(buf), "%d-%s", 42, "hi");
    if (n != 5) {
        exit(1);
    }
    if (memcmp(buf, "42-hi", 6) != 0) {  // includes the trailing NUL
        exit(1);
    }
    return *good;
}
