# As decrementer.ppc.s, but leaves MSR[IP] set so the exception table stays at
# 0xFFF00000 instead of 0x00000000.
#
# The MPC8xx comes out of reset with MSR[IP] set, and styx mapped the region
# holding those high vectors READ|WRITE with no EXEC - the only region in the
# processor's map without it - so a decrementer taken before firmware cleared IP
# died on a fetch-protection fault before its handler ran. This fixture is the
# regression test for nix/styx-emulator-build/patches/powerquicci-vectors.patch;
# it is loaded at 0xFFF00900 so `_vector` lands on the high decrementer vector.
    .section .text
    .globl _start

# ---- decrementer vector (0xFFF00900 with MSR[IP] set) ------------------
_vector:
    li      3, 0x5a           # marker: the handler ran
    lis     5, 0x7fff
    ori     5, 5, 0xffff
    mtspr   22, 5             # DEC = 0x7fffffff, so it will not fire again
    rfi

# ---- main --------------------------------------------------------------
    .balign 32
_start:
    li      3, 0
    li      5, 100
    mtspr   22, 5             # arm DEC: underflows on the first stride
    mfmsr   6                 # keep the reset MSR, IP included
    ori     6, 6, 0x8000      # + MSR[EE]
    mtmsr   6
_wait:
    cmpwi   3, 0
    beq     _wait
_done:
    nop
