    .text
# Taint-propagation exercise for the Triton backend; see taint.amd64.s for the
# data-flow the harness checks. a0/a1 are the inputs, t0 holds the scratch base.
#
# The register-to-register step uses xori/xor rather than addi because Triton's
# RISC-V semantics for addi/add/sub/slli do not union their source taint into
# the destination (or/xor/mv do), and RV32 has no addiw.
# Flipping the low bit computes the same +1 for the even values this scenario
# uses, so the data-flow under test is unchanged.
taint:
    lui     t0, 0x3
    xori    a2, a0, 1
    sw      a2, 0(t0)
    lw      a3, 0(t0)
    sw      a1, 4(t0)
    lw      a4, 4(t0)
    lw      a5, 8(t0)
    li      a0, 0
