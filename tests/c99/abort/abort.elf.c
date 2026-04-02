#include <stdlib.h>
int main() {
    char *bad = (char *)(size_t)0xdead0;
    abort();
    return *bad;
}
