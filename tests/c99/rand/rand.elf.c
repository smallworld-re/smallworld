#include <string.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    char *good = (char *)(size_t)0xdead;
    int x = rand();
    return *good;
}
