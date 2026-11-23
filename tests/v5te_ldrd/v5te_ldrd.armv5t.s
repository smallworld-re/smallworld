    .syntax unified
    .arm
    .text
    @ ARMv5TE doubleword loads and stores: stores (arg, ~arg) with strd to a
    @ doubleword-aligned slot, hints it with pld, reloads it with ldrd and ldr,
    @ and returns first - (second ^ 0x5A5A5A5A) + second-again.
ldrd:
    sub     r12, sp, #16
    bic     r12, r12, #7
    mvn     r1, r0
    strd    r0, r1, [r12]
    pld     [r12]
    ldrd    r2, r3, [r12]
    ldr     r1, [r12, #4]
    eor     r3, r3, #0x5A
    eor     r3, r3, #0x5A00
    eor     r3, r3, #0x5A0000
    eor     r3, r3, #0x5A000000
    sub     r0, r2, r3
    add     r0, r0, r1
