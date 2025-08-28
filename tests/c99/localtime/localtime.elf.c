#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
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
    // NOTE: Because of how we run our tests, localtime == gmtime

    struct tm *actual = localtime(&t);
    expected.tm_gmtoff = actual->tm_gmtoff;
    expected.tm_zone = actual->tm_zone;
    if(memcmp(&expected, actual, sizeof(expected))) {
        exit(1);
    }
    return *good;
}
