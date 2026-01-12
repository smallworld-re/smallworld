#include <stdlib.h>

void bad_jump() {
    void (*foobar)(void) = (void *)(size_t)0xdead0000l;
    foobar();
}

void bad_function_pointer(void (*foobar)(void)) {
    foobar();
}

void bad_return() {
    return;
}

int bad_if(int x) {
    if (x == 0) {
        return 44;
    } else {
        return 42;
    }
}

void bad_instruction() {
    __builtin_trap();
}

int bad_read(char *input) {
    return input[42];
}

int main() {
    bad_read(NULL);
}
