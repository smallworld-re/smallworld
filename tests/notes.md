missing
=======
function pointers
ABI violations

branch.s
========
reads from rdi
comparison of rdi and 100
outputs al (results from rdi)

call.s
======
foo:
    reads from edi
    calls bar
    outputs eax (results from bar's return)

bar:
    reads from rdi
    outputs eax (results from rdi)

dma.s
=====
reads from address 0x4142434445464748
outputs eax (results from address 0x4142434445464748)

float_branch.s
==============
reads from xmm0, xmm1
outputs xmm0 (results from xmm0 or (xmm0 and xmm1))

floats.s
========
reads from xmm0, xmm1
outputs xmm0 (results from xmm0 and xmm1)

recursion.s
===========
reads from edi
comparison with eax and 100
returns eax (results from edi or call)

rip_relative.s
==============
reads from xmm0
reads from memory relative to instruction pointer
returns xmm0 (results from xmm0 and memory)

square.s
========
reads from edi
returns eax (results from edi)

stack.s
=======
reads from rdi
reads from rdx
reads from stack (offset +8)
returns rax (results from rdi, rdx, and stack +8)

strlen.s
========
read rdi as pointer
returns eax (results 0 | computation with memory)

struct.s
========
read from rdi as pointer
read from esi
possible struct:
    [4 byte value] [4 byte pad]
    [pointer to like]
    [pointer to like]
    [4 byte value]
returns eax (can we figure out void return)