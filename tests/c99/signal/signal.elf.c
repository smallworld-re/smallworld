#include <signal.h>
#include <stdlib.h>

void myhandler(int arg) {
    return;
}

int main() {
    int *good = (int *)(size_t)0xdead;
    void (*handler)(int) = signal(SIGSEGV, myhandler);

    handler = signal(SIGSEGV, SIG_DFL);
    if(handler != myhandler) {
        exit(1);
    }
    return *good;
}
