/*
 * The libgcc __sync_* atomics, for linking ARMv5T C tests with zig.
 *
 * ARMv5 has no exclusive loads and stores, so zig's compiler-rt implements
 * its __atomic_* functions by calling these, which libgcc provides (via the
 * Linux kernel's cmpxchg helper) but zig doesn't. compiler-rt is a single
 * object, so every program that needs any of it references them all.
 *
 * The tests are single-threaded and never call these, so plain,
 * non-atomic definitions are enough to link. Clang won't let C redeclare
 * these names, which it treats as builtins, so each is defined under a
 * local name and given its libgcc symbol name with an asm label.
 */

#include <stdint.h>

#define SYMBOL(name) __asm__(#name)

#define SYNC_FETCH_AND(name, T, n, expr)                                       \
    T shim_fetch_and_##name##_##n(volatile T *p, T v)                          \
        SYMBOL(__sync_fetch_and_##name##_##n);                                 \
    T shim_fetch_and_##name##_##n(volatile T *p, T v) {                        \
        T old = *p;                                                            \
        *p = (expr);                                                           \
        return old;                                                            \
    }

#define SYNC_ALL(T, n)                                                         \
    SYNC_FETCH_AND(add, T, n, old + v)                                         \
    SYNC_FETCH_AND(sub, T, n, old - v)                                         \
    SYNC_FETCH_AND(and, T, n, old & v)                                         \
    SYNC_FETCH_AND(or, T, n, old | v)                                          \
    SYNC_FETCH_AND(xor, T, n, old ^ v)                                         \
    SYNC_FETCH_AND(nand, T, n, ~(old & v))                                     \
    SYNC_FETCH_AND(umin, T, n, old < v ? old : v)                              \
    SYNC_FETCH_AND(umax, T, n, old > v ? old : v)                              \
    T shim_lock_test_and_set_##n(volatile T *p, T v)                           \
        SYMBOL(__sync_lock_test_and_set_##n);                                  \
    T shim_lock_test_and_set_##n(volatile T *p, T v) {                         \
        T old = *p;                                                            \
        *p = v;                                                                \
        return old;                                                            \
    }                                                                          \
    T shim_val_compare_and_swap_##n(volatile T *p, T expected, T desired)      \
        SYMBOL(__sync_val_compare_and_swap_##n);                               \
    T shim_val_compare_and_swap_##n(volatile T *p, T expected, T desired) {    \
        T old = *p;                                                            \
        if (old == expected) {                                                 \
            *p = desired;                                                      \
        }                                                                      \
        return old;                                                            \
    }

SYNC_ALL(uint8_t, 1)
SYNC_ALL(uint16_t, 2)
SYNC_ALL(uint32_t, 4)
