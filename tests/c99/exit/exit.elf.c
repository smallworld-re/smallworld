#include <string.h>
#include <stdlib.h>

int main() {
    char *bad = (char *)(size_t)0xdead;
    
    exit(0);
    return *bad;
}
