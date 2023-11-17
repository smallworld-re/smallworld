BITS 64;
function:
        comisd  xmm0, [rel .LC2]
        je      .L3
        movsd   xmm0, QWORD [rel .LC1]
        jmp     .EXIT
.L3:
        movsd   xmm0, QWORD [rel .LC0]
        ret
.LC0:
        dq   2061584302
        dq   1074114068
.LC1:
        dq   -618475291
        dq   1071283961
.LC2:
        dq   1374389535
        dq   1074339512
.EXIT:
