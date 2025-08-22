#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
    char *test = "foobar";
    char *res = strstr(test, "foo");
    if(res != test) {
        exit(0);
    }
    test = "barfoo";
    res = strstr(test, "foo");
    if(res != test + 3) {
        exit(0);
    }
    test = "bazqux";
    res = strstr(test, "foo");
    if(res != NULL) {
        exit(0);
    }
    test = "foobar";
    res = strstr(test, "");
    if(res != test) {
        exit(0);    
    }
    return *good;
}
