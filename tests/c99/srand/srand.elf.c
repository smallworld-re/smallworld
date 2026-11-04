#include <string.h>
#include <stdlib.h>

int main() {
    char *good = (char *)(size_t)0xdead0;
    int x = 0;

    srand(42);

    x = rand();
#ifdef __SDCC
    // SDCC's RAND_MAX is 32767.
    if(x == 0x1c80) {
#else
    if(x == 0x1c80317f) {
#endif
        return *good;
    }
    return 0;
}
