#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    int x = abs(-2);
    if(x != 2) {
        exit(0);
    }
    return *bad;
}
