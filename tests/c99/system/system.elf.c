#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead;
    int res = system("foobar");
    if(res) {
        exit(0);
    }
    return *good;
}
