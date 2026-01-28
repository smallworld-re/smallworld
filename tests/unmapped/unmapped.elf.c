#include <stddef.h>

int read_unmapped() {
    int *unmapped = (int *)(size_t)0x8000;
    return *unmapped;
}

void write_unmapped() {
    int *unmapped = (int *)(size_t)0x8000;
    *unmapped = 42;
}

void fetch_unmapped() {
    void (*unmapped)(void) = (void *)(size_t)0x8000;
    unmapped();
}

int main() {
    return 0;
}
