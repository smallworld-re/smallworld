    .syntax unified
    .arm
    .text
    @ ARMv8 CRC32: fold the low byte, then the whole word, of the argument
    @ into a CRC-32 accumulator that starts at all ones.
crc:
    mvn     r1, #0
    crc32b  r1, r1, r0
    crc32w  r1, r1, r0
    mov     r0, r1
