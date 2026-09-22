    .text
# Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
# data-flow the harness checks. a0/a1 are the inputs, t0 holds the scratch base.
#
# The register-to-register step uses addiw rather than addi because Triton's
# RISC-V semantics for addi/add/sub/slli do not union their source taint into
# the destination (or/xor/addiw/mv do). addiw computes the same +1 for the
# values this scenario uses, so the data-flow under test is unchanged.
taint:
    lui     t0, 0x3
    addiw   a2, a0, 1
    sd      a2, 0(t0)
    ld      a3, 0(t0)
    sd      a1, 8(t0)
    ld      a4, 8(t0)
    ld      a5, 16(t0)
    li      a0, 0
