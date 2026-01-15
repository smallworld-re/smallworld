#include <stdlib.h>

/*********************************************
 *** Functions for legit function pointers ***
 *********************************************/
void foo(void) {
    __builtin_trap();
}

void bar(void) {
    __builtin_trap();
}

void baz(void) {
    __builtin_trap();
}
void (*callees[])(void) = {
    foo,
    bar,
    baz
};

/************************
 *** Early exit tests ***
 ************************/

void early_lost(void) {
    // Angr and Unicorn take separate code paths

    // TODO: How would this happen without a diverge?
}

void early_halt_deadend_bounds(void) {
    // Angr halts before unicorn because of bounds

    // TODO: How would this happen without a diverge?
}

void early_halt_deadend_mmap(void) {
    // Angr halts before unicorn because of memory map

    // TODO: How would this happen without a diverge?
}


void early_halt_unconstrained_call(int choice) {
    // Angr halts before unicorn because of an unconstrained call target.
    callees[choice]();
}

void early_halt_unconstrained_return(void) {
    // Angr halts before unicorn because of an unconstrained return

    // TODO: How would this happen without an OOB or memory error?
}

int early_halt_unconstrained_jump(int x) {
    // Angr halts before unicorn because of an unconstrained jump

    // TODO: How do I even make this happen?
    switch(x) {
        case 36:
            return 42;
        case 19:
            return 99;
        case 12:
        case 99:
            return 45;
        default:
            return 0;
    }
}

int early_halt_diverged(int x) {
    // Angr halts before unicorn because of an unconstrained branch
    if (x == 0) {
        return 44;
    } else {
        return 42;
    }
}

void early_illegal(void) {
    // Angr halts before unicorn because of an unsupported instruction.

    // TODO: This is essentially impossible to do cross-platform.
    // The main examples I have are unsupported FPU instructions in a few ISAs.
}

/*****************
 *** OOB tests ***
 *****************/

void oob_deadend_bounds(void) {
    // Crash because of an out-of-bounds execution

    // TODO: This requires surgery on the code bounds.
    // It will detect an unmapped access first.
}

void oob_deadend_mmap(void) {
    // Crash because of an unmapped execution.

    // Yes, for now this is the same as the bounds version;
    // the difference will have to be in the harness.
    void (*foobar)(void) = (void *)(size_t)0xdead0000l;
    foobar();
}

void oob_unconstrained_call(void (*foobar)(void)) {
    // Crash because of an unconstrained function call
    foobar();
}

void oob_unconstrained_return(void) {
    // Crash because of an unconstrained return
    return;
}

void oob_unconstrained_jump(long x) {
    // Crash because of an unconstrained jump target.

    // This is thoroughly contrived,
    // but compilers will use something similar internally for jump tables.
    void (*foobar)(void) = (void *)(size_t)(0xdead0000l + x);
    foobar();
}

void oob_diverged(void) {
    // Crash because one possible fork of an unconstrained branch is a halt.

    // TODO: I have no idea how to implement this without assembly.
}

/*********************
 *** Illegal tests ***
 *********************/
void illegal_undecodable() {
    // Crash because of an instruction that's not an instruction
    __asm__(".word 0xffff");
}

void illegal_decodable() {
    // Crash because of a faulting instruction
    // Generating confirmed vs unconfirmed is way too deep in the weeds of Unicorn and Vex
    __builtin_trap();
}

/********************
 *** Memory tests ***
 ********************/
int mem_read_constrained() {
    // Crash because of a read from an unmapped address
    int *foobar = (void *)(size_t)0xdead0000l;
    return *foobar; 
}

int mem_read_unconstrained(int *x) {
    // Crash because of a read from an unconstrained address
    return *x; 
}

void mem_write_constrained() {
    // Crash because of a write to an unmapped address
    int *foobar = (void *)(size_t)0xdead0000l;
    *foobar = 42; 
}

void mem_write_unconstrained(int *x) {
    // Crash because of a write to an unconstrained address
    *x = 42; 
}


int main() {
    return 0;
}
