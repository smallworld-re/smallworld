#include <stddef.h>

int read_unmapped() {
    int *unmapped = (int *)(size_t)0xdead;
    return *unmapped;
}

void write_unmapped() {
    int *unmapped = (int *)(size_t)0xdead;
    *unmapped = 42;
}

void fetch_unmapped() {
    void (*unmapped)(void) = (void *)(size_t)0xdead;
    unmapped();
}

int main() {
    return 0;
}
