#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead;
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
    return *good;
}
