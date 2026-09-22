#include <math.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead0;

    // fabs takes its argument as a double and returns one, so this exercises
    // the calling convention's floating-point argument register(s) end to end
    // -- the model reads arg0 from the first FP argument register and returns
    // through the FP return register.
    if (fabs(-3.5) != 3.5) {
        exit(1);
    }
    if (fabs(2.25) != 2.25) {
        exit(1);
    }
    if (fabs(0.0) != 0.0) {
        exit(1);
    }

    return *good;
}
