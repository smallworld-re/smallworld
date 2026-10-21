    .syntax unified
    .thumb
    .text
    @ ARMv8-M stack limits: set both limit registers to the argument and
    @ read them back. Bits [2:0] are RES0, so each reads back 8-aligned.
    @ Returns msplim + psplim.
stacklimit:
    msr     msplim, r0
    msr     psplim, r0
    mrs     r1, msplim
    mrs     r2, psplim
    add     r0, r1, r2
