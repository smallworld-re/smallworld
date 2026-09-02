#include <stdio.h>
#include <stdlib.h>

// perror() is modeled as a benign no-op (we don't emit to stderr); the test
// just confirms the call is intercepted and returns so execution continues.
int main() {
    char *good = (char *)(size_t)0xdead0;
    perror("test error");
    return *good;
}
