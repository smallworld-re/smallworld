#define _XOPEN_SOURCE 500
#include <signal.h>
#include <stdlib.h>

void myhandler(int arg) {
    return;
}

int main() {
    int *good = (int *)(size_t)0xdead;
    void (*handler)(int) = bsd_signal(SIGSEGV, myhandler);

    handler = bsd_signal(SIGSEGV, SIG_DFL);
    if(handler != myhandler) {
        exit(1);
    }
    return *good;
}
