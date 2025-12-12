#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead;
    char *test = NULL; 
    char *res = NULL;

    test = "foobar";
    res = strpbrk(test, "foo");
    if(res != test) {
        exit(0);
    }
    test = "barfoo";
    res = strpbrk(test, "foo");
    if(res != test + 3) {
        exit(0);
    }
    test = "bazqux";
    res = strpbrk(test, "foo");
    if(res != NULL) {
        exit(0);
    }
    test = "foobar";
    res = strpbrk(test, "");
    if(res != NULL) {
        exit(0);
    }
    return *good;
    
}
