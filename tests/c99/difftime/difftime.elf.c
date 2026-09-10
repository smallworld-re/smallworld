#include <stdlib.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    /* C's difftime(time1, time0) returns time1 - time0, so the first
       argument is the minuend: difftime(43, 42) == 1.0. */
    time_t time1 = 43;
    time_t time0 = 42;
    double expected = 1.0;
    double actual = difftime(time1, time0);
    if(expected != actual) {
        exit(1);
    }
    return *good;
}
