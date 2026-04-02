#include <stdlib.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead0l;
    clock_t c = clock();
    return *good;
}
