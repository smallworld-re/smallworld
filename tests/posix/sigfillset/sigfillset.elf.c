#include <signal.h>
#include <stdlib.h>

int main() {
    int *good = (int *)(size_t)0xdead;
    sigset_t set = {0};
    
    if(sigfillset(&set)) {
        exit(1);
    }

#if __WORDSIZE == 64
    if(set.__val[0] != 0xfffffffe7fffffffl) {
        exit(1);
    }
#ifdef _mips
    if(set.__val[1] != 0xffffffffffffffffl) {
        exit(1);
    }
#endif//_mips
#elif __WORDSIZE == 32
    if(set.__val[0] != 0x7fffffffl ||
        set.__val[1] != 0xfffffffel) {
        exit(1);
    }
#ifdef _mips
    if(set.__val[2] != 0xffffffffl ||
        set.__val[3] != 0xffffffffl) {
        exit(1);
    }
#endif//_mips
#else
#error "What the heck is your wordsize?"
#endif //__WORDSIZE
    return *good;
}
