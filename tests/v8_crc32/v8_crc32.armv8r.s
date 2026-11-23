    .syntax unified
    .arm
    .text
    @ ARMv8 CRC32: fold the low byte, halfword and word of the argument into
    @ a CRC-32 accumulator that starts at all ones, then the same into it with
    @ the CRC-32C polynomial.
crc:
    mvn     r1, #0
    crc32b  r1, r1, r0
    crc32h  r1, r1, r0
    crc32w  r1, r1, r0
    crc32cb r1, r1, r0
    crc32ch r1, r1, r0
    crc32cw r1, r1, r0
    mov     r0, r1
