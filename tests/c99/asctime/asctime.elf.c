#include <time.h>
#include <stdlib.h>
#include <string.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    struct tm st = {
        .tm_sec = 0,
        .tm_min = 9,
        .tm_hour = 15,
        .tm_mday = 14,
        .tm_mon = 2,
        .tm_year = 125,
        .tm_wday = 0,
        .tm_yday = 0,
        .tm_isdst = 0
    };
    char *expected = "Sun Mar 14 15:09:00 2025\n";
    char *actual = asctime(&st);
    if(strcmp(expected, actual)) {
        exit(1);
    }

    return *good;

}
