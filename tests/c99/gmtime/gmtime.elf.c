#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main() {
    int *good = (int *)(size_t)0xdead0;
    time_t t = 0;
    struct tm expected = {
        .tm_sec = 0,
        .tm_min = 0,
        .tm_hour = 0,
        .tm_mday = 1,
        .tm_mon = 0,
        .tm_year = 70,
        .tm_wday = 4,
        .tm_yday = 0,
        .tm_isdst = 0
    };

    struct tm *actual = gmtime(&t);
    expected.tm_gmtoff = actual->tm_gmtoff;
    expected.tm_zone = actual->tm_zone;
    if(memcmp(&expected, actual, sizeof(expected))) {
        exit(1);
    }

    // A Sunday (1970-01-04 00:00:00 UTC) must yield tm_wday == 0. The weekday
    // shift was non-modular, so Sunday came out as 7 instead of 0.
    time_t sunday = 259200;
    struct tm sunday_expected = {
        .tm_sec = 0,
        .tm_min = 0,
        .tm_hour = 0,
        .tm_mday = 4,
        .tm_mon = 0,
        .tm_year = 70,
        .tm_wday = 0,
        .tm_yday = 3,
        .tm_isdst = 0
    };
    struct tm *sunday_actual = gmtime(&sunday);
    sunday_expected.tm_gmtoff = sunday_actual->tm_gmtoff;
    sunday_expected.tm_zone = sunday_actual->tm_zone;
    if(memcmp(&sunday_expected, sunday_actual, sizeof(sunday_expected))) {
        exit(1);
    }

    return *good;
}
