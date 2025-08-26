#include <signal.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    sigset_t set = {0};
    set.__val[0] = -1;
    
    if(sigemptyset(&set)) {
        exit(1);
    }
    if(set.__val[0] != 0) {
        exit(1);
    }
    return *good;
}
