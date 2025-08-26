#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

int main() {
    int *good = (int*)(size_t)0xdead;
    sigset_t oldset = {0};
    sigset_t newset = {0};
    newset.__val[0] = 0x200;

    if(pthread_sigmask(SIG_SETMASK, &newset, NULL)) {
        exit(1);
    }

    if(pthread_sigmask(SIG_UNBLOCK, &newset, &oldset)) {
        exit(1);
    }
    // Tests the previous action
    if(oldset.__val[0] != newset.__val[0]) {
        exit(1);
    }
    
    if(pthread_sigmask(SIG_BLOCK, &newset, &oldset)) {
        exit(1);
    }
    // Tests the previous action
    if(oldset.__val[0] != 0) {
        exit(1);
    }

    if(pthread_sigmask(0, NULL, &oldset)) {
        exit(1);
    }
    // Tests the previous action
    if(oldset.__val[0] != newset.__val[0]) {
        exit(1);
    }
    
    return *good;
}
