    .text
    // Every instruction in the AArch64 hint space other than nop, wfe and wfi.
    // On ARMv8.0 all of them are no-ops; on later cores the pointer
    // authentication ones sign or authenticate a register, so each sign is
    // paired with its authenticate, which gives the register back. Returns
    // 2 * arg either way. Written as hint #n, because an ARMv8.0 assembler
    // doesn't accept the later mnemonics.
hints:
    hint    #34             // bti c
    hint    #25             // paciasp
    hint    #27             // pacibsp
    hint    #24             // paciaz
    mov     x16, #0x1234
    mov     x17, x0
    hint    #8              // pacia1716
    hint    #12             // autia1716
    hint    #10             // pacib1716
    hint    #14             // autib1716
    hint    #28             // autiaz
    hint    #31             // autibsp
    hint    #29             // autiasp
    hint    #7              // xpaclri
    hint    #32             // bti
    hint    #36             // bti j
    hint    #38             // bti jc
    hint    #1              // yield
    hint    #4              // sev
    hint    #5              // sevl
    hint    #6              // dgh
    hint    #16             // esb
    hint    #17             // psb csync
    hint    #18             // tsb csync
    hint    #20             // csdb
    hint    #0x7f           // unallocated: executes as a no-op
    add     x0, x0, x17
