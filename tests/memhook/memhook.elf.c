#include <stddef.h>
#include <stdlib.h>
int main() {
    // Test: Hook 8 bytes at 0x1000, access 1 byte at 0x1004
    // Expected: Access 1 byte at 0x1004
    char       *foo = (void *)(size_t)0x1004;
    // Test: Hook 8 bytes at 0x100c, access 8 bytes at 0x1010
    // Expected (32-bit): Access 4 bytes at 0x1010
    // Expected (64-bit): Access 8 bytes at 0x100c
    long long  *bar = (void *)(size_t)0x1010;
    // Test: Hook 8 bytes at 0x101c, access 8 bytes at 0x1020
    // Expected (32-bit): Access 4 bytes at 0x1024
    // Expected (64-bit): Access 8 bytes at 0x1024
    long long  *baz = (void *)(size_t)0x1020;
    // Test: Hook 1 byte at 0x1034, access 8 bytes at 0x1030
    // Expected (32-bit): Access 4 bytes at 0x1030
    // Expected (64-bit): Access 8 bytes at 0x1030
    long long  *qux = (void *)(size_t)0x1030;
    
    char c = *foo;
    long long x = *bar;
    long long y = *baz; 
    long long z = *qux;

    *foo = 42;
    *bar = 42ll;
    *baz = 42ll;
    *qux = 42ll;
    exit(0);
}
