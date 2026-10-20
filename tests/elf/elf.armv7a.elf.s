    .arch armv7-a
	.fpu vfpv3-d16
    .eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 6
	.eabi_attribute 34, 0
	.eabi_attribute 18, 4
    .text
    .align  2
    .globl  _start
    .syntax unified
    .arm
    .type   _start, %function
_start:
    # Load argc
    ldr     r2, [sp]
    
    # If argc != 2, leave
    cmp     r2, #2
    bne     .L2

    # Load argv
    ldr     r1, [sp,#4]
    # Load argv[1]
    ldr     r1, [r1,#4]
    
    mov     r0, #0

.L3:
    # for(i = 0; argv[1][i] != '\0'; i++);
    add     r2, r1, r0
    ldrb    r2, [r2]
    
    cmp     r2, #0
    beq     .L1
    add     r0, r0, #1
    b       .L3

.L2:
    # Failure; return -1
    mov     r0, #-1

.L1:
    # Leave, by any means necessary
    bx      lr
    .size _start, .-_start
     
