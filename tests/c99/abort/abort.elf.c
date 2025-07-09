#include <stdlib.h>
int main() {
    char *bad = (char *)(size_t)0xdead;
    abort();
    return *bad;
}
