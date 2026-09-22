#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead0;
    double x;

    x = atof("2.5");
    if (x != 2.5) {
        exit(0);
    }
    // A leading sign is part of the number. Real atof("-1.5") == -1.5 and
    // atof("+3.0") == 3.0; the previous model dropped the sign and returned
    // 0.0 for any signed literal. All constants here are exactly
    // representable, so the == comparisons are safe.
    x = atof("-1.5");
    if (x != -1.5) {
        exit(0);
    }
    x = atof("+3.0");
    if (x != 3.0) {
        exit(0);
    }
    x = atof("42");
    if (x != 42.0) {
        exit(0);
    }
    x = atof("foobar");
    if (x != 0.0) {
        exit(0);
    }
    return *bad;
}
