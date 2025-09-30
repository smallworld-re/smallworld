#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

void exit_handler(void) {
    return;
}

int evil(int unused, ...) {
    va_list args;
    va_start(args, unused);
    vprintf("%s\n", args);
    va_end(args);
    return 0;
}

int main() {
    int *good = (int *)(size_t)0xdead;
    time_t t = time(NULL);
    const char *ct = ctime(&t);
    atexit(exit_handler);
    system("/bin/true");
    evil(0, ct);   
 
    return *good;
}
