#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    time_t expected = 1741969920;
    struct tm st = {
        .tm_sec = 0,
        .tm_min = 92,
        .tm_hour = 15,
        .tm_mday = 14,
        .tm_mon = 2,
        .tm_year = 125,
        .tm_wday = 0,
        .tm_yday = 0,
        .tm_isdst = 0
    };

    time_t actual = mktime(&st);
    if(expected != actual) {
        exit(0);
    }
    return *good;
}
