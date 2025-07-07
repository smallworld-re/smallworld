#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
    int x = 0;

    srand(42);

    x = rand();
    if(x == 0x1c80317f) {
        return *good;
    }
    return 0;
}
