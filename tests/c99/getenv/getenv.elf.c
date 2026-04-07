#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead0l;
    getenv("foobar");
    return *good;
}
