#include <stdlib.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    time_t time0 = 42;
    time_t time1 = 43;
    double expected = 1.0l;
    double actual = difftime(time0, time1);
    if(expected != actual) {
        exit(1);
    }
    return *good;
}
