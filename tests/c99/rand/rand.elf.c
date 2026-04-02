#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead0;
    int x = rand();
    return *good;
}
