BITS 64;
; Takes two arguments, if the second is greater than / equal then return the difference between the second and first.
; Otherwise it returns the not the first.
function:
        comisd  xmm1, xmm0
        jnb     .L8
        cvttsd2si       rax, xmm0
        pxor    xmm1, xmm1
        not     rax
        cvtsi2sd        xmm1, rax
        movapd  xmm0, xmm1
        jmp     .EXIT
.L8:
        subsd   xmm1, xmm0
        movapd  xmm0, xmm1
        ret
.EXIT:
