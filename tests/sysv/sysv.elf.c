#include <stddef.h>
#include <stdarg.h>

void foo(
    unsigned long long x, 
    unsigned int y, 
    unsigned long long z, 
    unsigned int a, 
    unsigned long long b, 
    ...
    ) {
    return;
}

void bar(
    unsigned int x,
    float y,
    double z,
    double a,
    double b,
    double c
    ) {
    return;
}

int main() {
    char *good = (char *)(size_t)0xdead;
    foo(
        0x0123456789abcdefll, 
        0x87654321, 
        0x08192a3b4c5d6e7fll, 
        0, 
        0xf0e1d2c3b4a59687ll, 
        0ll,
        0xc001d00d,
        0,
        0x1337beefll);
    bar(
        0x0,
        0.25,
        0.21l,
        1.0l,
        10.0l,
        100.0l
    );
    return *good;
}
