#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int *good = (int *)(size_t)0xdead;
    const char *fmt = "%a %A %b %B %c %C %d %D %e %F %g %G %h %H %I %j %k %l %m %M %n %P %r %s %S %t %T %u %U %V %w %W %x %X %y %Y %z %Z";
    const char *expected = "Sun Sunday Mar March Sun Mar 14 15:26:00 2025 20 14 03/14/25 14 2025-03-14 24 2024 Mar 15 03 001 15  3 03 26 \n pm 03:26:00 PM 1741965960 00 \t 15:26:00 7 01 52 0 00 03/14/25 15:26:00 25 2025 +0000 UTC";
    struct tm st = {
        .tm_sec = 0,
        .tm_min = 26,
        .tm_hour = 15,
        .tm_mday = 14,
        .tm_mon = 2,
        .tm_year = 125,
        .tm_wday = 0,
        .tm_yday = 0,
        .tm_isdst = 0
    };
    char buf[0x1000];
    strftime(buf, 0xfff, fmt, &st);
 
    if(strcmp(expected, buf)) {
        exit(1);
    }
 
    return *good;
}
