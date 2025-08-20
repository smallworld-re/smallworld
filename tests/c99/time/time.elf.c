#include <stdlib.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    time_t a = 0;
    time_t b = time(&a);
    if(a != b) {
        exit(1);
    }
    return *good;
}
