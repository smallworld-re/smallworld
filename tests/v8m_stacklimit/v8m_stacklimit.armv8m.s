    .syntax unified
    .thumb
    .text
    @ ARMv8-M stack limits: set msplim to the argument and psplim to the
    @ argument + 0x80, and read them back. Bits [2:0] are RES0, so each reads
    @ back 8-aligned. Returns msplim | psplim << 16, so swapped or shared
    @ limits show.
stacklimit:
    msr     msplim, r0
    add     r1, r0, #0x80
    msr     psplim, r1
    mrs     r1, msplim
    mrs     r2, psplim
    orr     r0, r1, r2, lsl #16
