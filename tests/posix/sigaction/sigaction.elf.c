#include <signal.h>
#include <stdlib.h>

void myhandler(int arg) {
    return;
}

int main() {
    int *good = (int *)(size_t)0xdead;
    struct sigaction oldact = {0};
    struct sigaction newact = {0};

    newact.sa_handler = myhandler;
    newact.sa_mask.__val[0] = 1;
    newact.sa_flags = SA_RESTART;

    if(sigaction(SIGSEGV, &newact, &oldact)) {
        exit(1);
    }
    if(sigaction(SIGSEGV, &oldact, &newact)) {
        exit(1);
    }
    if(newact.sa_handler != myhandler) {
        exit(1);
    }
    if(newact.sa_mask.__val[0] != 1) {
        exit(1);
    }
    if(newact.sa_flags & SA_RESTART == 0) {
        exit(1);
    }
    return *good;
}
