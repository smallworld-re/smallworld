#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead0;
    char *res = NULL;
    char *test = "foobar";
    res = strrchr(test, 'f');
    if(res != test) {
        exit(0);
    }
    test = "foofoo";
    res = strrchr(test, 'f');
    if(res != test + 3) {
        exit(0);
    }
    test = "bazqux";
    res = strrchr(test, 'f');
    if(res != NULL) {
        exit(0);
    }
    // C masks the value to unsigned char before searching, so 0x100 | 'f'
    // searches for 'f'; in "foofoo" the last 'f' is at index 3. The previous
    // model rejected any value > 255 and returned NULL.
    test = "foofoo";
    res = strrchr(test, 0x100 + 'f');
    if(res != test + 3) {
        exit(0);
    }
    return *good;
}
