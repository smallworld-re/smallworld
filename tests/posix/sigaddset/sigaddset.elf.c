#include <signal.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    sigset_t set = {0};
    
    if(sigaddset(&set, SIGSEGV)) {
        exit(1);
    }
    if(set.__val[0] != 0x400) {
        exit(1);
    }
    return *good;
}
