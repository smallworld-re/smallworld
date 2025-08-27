#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    time_t t = 1741964940;
    char *expected = "Fri Mar 14 15:09:00 2025\n";
    char *actual = ctime(&t);
    if(strcmp(expected, actual)) {
        puts(expected);
        puts(actual);
        exit(1);
    }

    return *good;

}
