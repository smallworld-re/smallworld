    # Berkeley TestFloat kernels for i386, SSE scalar.
    #
    # Four loops, one per (precision, arity), each at a fixed offset so the
    # harness can pick an entry point without parsing the binary.  The
    # arithmetic instruction of each loop is patched in by the harness: the SSE
    # scalar ops share the shape <prefix> 0F <op> <modrm>, so addss/subss/mulss/
    # divss differ only in the third byte and sqrtss differs in that byte plus
    # its modrm - all four bytes wide, which keeps this to one source file per
    # architecture instead of one per operation.
    #
    # SSE, not x87.  The x87 stack evaluates at 80-bit extended precision under
    # its reset control word, so `fadd` on two f32 operands rounds once to 64-bit
    # significand and again on store - double rounding that disagrees with
    # TestFloat's single-rounding f32/f64 reference for reasons that have nothing
    # to do with the emulator under test.  SSE computes at the operand's own
    # width, which is what the reference models.  (docs/concepts/platforms/
    # float_support.csv records x87 unsupported and SSE supported for the same
    # reason.)
    #
    # Contract (identical on every architecture):
    #   esi = input base, edi = output base, ecx = case count (> 0)
    #   inputs are packed operands, little-endian, no padding
    #   each iteration writes one result to the output cursor
    #   every loop leaves via the shared `done` label at offset 0x100
    #
    # MXCSR is left alone.  Its reset value 0x1F80 is round-to-nearest-even with
    # FTZ and DAZ clear and every exception masked, which is exactly the mode
    # TestFloat verifies against, and all four backends we run were measured to
    # start there (see the notes in testfloat_arch/i386.py).  So unlike SuperH -
    # whose FPSCR reset value has RM=01, toward zero - no control-word prologue is
    # needed, and the entry offset is the top of the loop.
    #
    # x86 has no post-increment addressing, so the cursors advance explicitly
    # after the store; the patched instruction therefore sits at a fixed offset
    # from the entry (+9 with two operands loaded, +4 with one) rather than after
    # a prologue.
    .text

    .org 0x00
f32_binary:
.Lf32_binary:
    movss   (%esi), %xmm0           # operand a
    movss   4(%esi), %xmm1          # operand b
    addss   %xmm1, %xmm0            # PATCHED: addss/subss/mulss/divss
    movss   %xmm0, (%edi)
    addl    $8, %esi
    addl    $4, %edi
    decl    %ecx
    jnz     .Lf32_binary
    jmp     done

    .org 0x40
f32_unary:
.Lf32_unary:
    movss   (%esi), %xmm0
    sqrtss  %xmm0, %xmm0            # PATCHED: sqrtss
    movss   %xmm0, (%edi)
    addl    $4, %esi
    addl    $4, %edi
    decl    %ecx
    jnz     .Lf32_unary
    jmp     done

    # The double-precision loops are byte-for-byte the single-precision ones with
    # the F3 prefix swapped for F2 and the strides doubled.  They still name
    # xmm0/xmm1: unlike SuperH's DR pairs there is no register-numbering
    # constraint tied to precision on x86, the prefix alone selects the width.
    .org 0x80
f64_binary:
.Lf64_binary:
    movsd   (%esi), %xmm0
    movsd   8(%esi), %xmm1
    addsd   %xmm1, %xmm0            # PATCHED: addsd/subsd/mulsd/divsd
    movsd   %xmm0, (%edi)
    addl    $16, %esi
    addl    $8, %edi
    decl    %ecx
    jnz     .Lf64_binary
    jmp     done

    .org 0xC0
f64_unary:
.Lf64_unary:
    movsd   (%esi), %xmm0
    sqrtsd  %xmm0, %xmm0            # PATCHED: sqrtsd
    movsd   %xmm0, (%edi)
    addl    $8, %esi
    addl    $8, %edi
    decl    %ecx
    jnz     .Lf64_unary
    jmp     done

    .org 0x100
done:
    nop
