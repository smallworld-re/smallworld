#include <stdint.h>
#include "stdio.h"
#include "stdlib.h"

void test_void(void) {
    return;
}

int32_t test_int32(int32_t arg1) {
    return arg1;
}

uint32_t test_uint32(uint32_t arg1) {
    return arg1;
}

int64_t test_int64(int64_t arg1) {
    return arg1;
}

uint64_t test_uint64(uint64_t arg1) {
    return arg1;
}

float test_float(float arg1) {
    return arg1;
}

double test_double(double arg1) {
    return arg1;
}

// model this function
int test(
    void (*_test_void)(void),
    int32_t (*_test_int32)(int32_t),
    uint32_t (*_test_uint32)(uint32_t),
    int64_t (*_test_int64)(int64_t),
    uint64_t (*_test_uint64)(uint64_t),
    float (*_test_float)(float),
    double (*_test_double)(double)
) {
    // stub to be modeled.
    // for each argument function pointer,
    // call with a test value and verify
    // it returns sucessfully.
    // return 0 for success, 1 for failure.
    return 1;
}

int main() {
    char *good = (char *)(size_t)0xdead;

    // test argument types
    if (
        test(
            test_void,
            test_int32,
            test_uint32,
            test_int64,
            test_uint64,
            test_float,
            test_double
        ) != 0
    )
    {
        return 1;
    }

    return *good;
}
