#include <signal.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    sigset_t set = {0};
    set.__val[0] = -1;

    // Expect to have no signals pending    
    if(sigpending(&set)) {
        exit(1);
    }
    if(set.__val[0] != 0) {
        exit(1);
    }
    return *good;
}
