Colorizer Analysis
==================

This is a kind of simple poor-man's (or woman's) dynamic data flow
analysis, that is, it gives one the ability to follow the flow of
specific values from instruction to instruction.
The fundamental idea, here, is based on the presumption that, if we can
initialize registers and memory with random (but known) bytes, then we can
know that their contents are being re-used later in the code
when we see the values again.
These random values are called *colors*.
To our knowledge, this use of the term was coined in the NDSS paper
describing the REDQUEEN fuzzer [#A]_.

The ``Colorizer`` class, itself, is fairly simple.
It takes, as input to its ``run`` method, some initial machine state.
Then, it uses the ``TraceExecution`` analysis both to generate an
execution, but also to investigate colors before and
after each instruction executes.

- Before the instruction executes, every read made by the instruction
  is examined: there are two possibilities.
  
  - It is a *read-def* if it is new color. In other words, this is
    the first read or use observed of this color; this means it
    is an input of the trace,
  - It is a *read-flow* if it is not a new color. It is a color that
    has been previously observed, indicating there is a data-flow
    between that first use and this one.
    
- After the instruction executes, every write made by the instruction
  is examined: here, too, there are two possibilities.
  
  - it is a *write-def* if it is new color. This is a value computed by
    the instruction.
  - it is a *write-copy* if it not a new color. The value being
    written is a copy of a previously observed (when read or written)
    color.
      
The ``Colorizer`` relies upon the Capstone disassembler which provides
use/def information about every instruction.
This would, for example, tell us that the ``imul eax, eax`` instruction
*uses* or *reads* the ``eax`` register, and *defines* or *writes* the ``eax``
register.

Note that the establishment of colors is implicit and happens,
by inspection, whenever an instruction reads or writes a value.
If it is a new value, then a new color is added to a set being tracked
and further reads and writes will be with respect to that.

This analysis is often used in conjunction with a helper function
``smallworld.colorizer.randomize_uninitialized`` which takes a machine state
and examines it, determining any registers or memory bytes that are
uninitialized, which it proceeds to set to random values.
This is important since otherwise those will contain 0, which is not
a very useful color. 
The colorizer's analysis depends upon the values in registers or memory being
unique and therefore characterstic and while ``randomize_uninitialized``
doesn't guarantee this, it is very effective.

Note that the colorizer's constructor takes a parameter ``min_color`` which
is used to set a minimum value below which a value will not be considered
a color.
Obviously, values like 0 and 1 make terrible colors since they are common
in logic and data.
From experience a minimum color of 30-50 seems good, but extensive testing
or study of this aspect of colorizer data-flow analysis has not happened.
The default value used if this argument is not passed to the constructor is
a minimum color of 0x80, which is fairly conservative.

The colorizer generates output as two kinds of hints indicating the
observation of a dynamic value regarded as a *color*.

- ``DynamicRegisterValueHint`` -- the value is in a register
- ``DynamicMemoryValueHint`` -- the value is in memory

Both hints include all of the following fields

.. code-block::

    pc: int               # the program counter
    instruction_num: int  # insctruction count in trace
    exec_id: int          # trace number if multiple
    dynamic_value: int    # the actual dynamic value
    color: int            # the color
    size: int             # size of value in bytes
    use: bool             # true if a 'use' or 'read', else a 'def' or 'write'    
    new: bool             # true if first observation

For the register version of the hint we also have a field ``reg_name``.
For the memory version, all of the following additionally.

.. code-block::

    address: int     # the concrete address of the memory
    base: str        # if a BSID used to compute address
                     # this will be register base
    index: str       # .. index scale offset
    scale: int       # 
    offset: int

  

Example Use
-----------

The following function ``call_sym`` illustrates one way in which this kind
of analysis can be of use.

.. code-block::

       [0x00001060]> pdf @ sym.call_sys
		   ; CALL XREF from sub.main_1243 @ 0x1260(x)
       ┌ 250: sym.call_sys (int64_t arg1);
       │ `- args(rdi) vars(6:sp[0x10..0x30])
       │           0x00001149      55             push rbp
       │           0x0000114a      4889e5         mov rbp, rsp
       │           0x0000114d      4883ec30       sub rsp, 0x30
       │           0x00001151      48897dd8       mov qword [var_28h], rdi    ; arg1
       │           0x00001155      488b45d8       mov rax, qword [var_28h]
       │           0x00001159      488945f8       mov qword [string], rax
       │           0x0000115d      488b45f8       mov rax, qword [string]
       │           0x00001161      48c1e818       shr rax, 0x18
       │           0x00001165      8945ec         mov dword [var_14h], eax
       │           0x00001168      c745e80900..   mov dword [var_18h], 9
       │           0x0000116f      8b45ec         mov eax, dword [var_14h]
       │           0x00001172      488d158b0e..   lea rdx, str.n_d_n          ; 0x2004 ; "n=%d\n"
       │           0x00001179      89c6           mov esi, eax
       │           0x0000117b      4889d7         mov rdi, rdx                ; const char *format
       │           0x0000117e      b800000000     mov eax, 0
       │           0x00001183      e8b8feffff     call sym.imp.printf         ; int printf(const char *format)
       │           0x00001188      488b45f8       mov rax, qword [string]
       │           0x0000118c      488d15770e..   lea rdx, str.a_lX_n         ; 0x200a ; "a=%lX\n"
       │           0x00001193      4889c6         mov rsi, rax
       │           0x00001196      4889d7         mov rdi, rdx                ; const char *format
       │           0x00001199      b800000000     mov eax, 0
       │           0x0000119e      e89dfeffff     call sym.imp.printf         ; int printf(const char *format)
       │           0x000011a3      b8efbeadde     mov eax, 0xdeadbeef
       │           0x000011a8      483145f8       xor qword [string], rax
       │           0x000011ac      c745f40000..   mov dword [var_ch], 0
       │       ┌─< 0x000011b3      eb21           jmp 0x11d6
       │       │   ; CODE XREF from sym.call_sys @ 0x11dc(x)
       │      ┌──> 0x000011b5      8b45f4         mov eax, dword [var_ch]
       │      ╎│   0x000011b8      4898           cdqe
       │      ╎│   0x000011ba      488d148500..   lea rdx, [rax*4]
       │      ╎│   0x000011c2      488d05772e..   lea rax, obj.mints          ; 0x4040 ; U"=J`\W9J\x1a\v"
       │      ╎│   0x000011c9      8b0402         mov eax, dword [rdx + rax]
       │      ╎│   0x000011cc      4898           cdqe
       │      ╎│   0x000011ce      480145f8       add qword [string], rax
       │      ╎│   0x000011d2      8345f401       add dword [var_ch], 1
       │      ╎│   ; CODE XREF from sym.call_sys @ 0x11b3(x)
       │      ╎└─> 0x000011d6      8b45f4         mov eax, dword [var_ch]
       │      ╎    0x000011d9      3b45e8         cmp eax, dword [var_18h]
       │      └──< 0x000011dc      7cd7           jl 0x11b5
       │           0x000011de      488b45f8       mov rax, qword [string]
       │           0x000011e2      488d15210e..   lea rdx, str.a_lX_n         ; 0x200a ; "a=%lX\n"
       │           0x000011e9      4889c6         mov rsi, rax
       │           0x000011ec      4889d7         mov rdi, rdx                ; const char *format
       │           0x000011ef      b800000000     mov eax, 0
       │           0x000011f4      e847feffff     call sym.imp.printf         ; int printf(const char *format)
       │           0x000011f9      8b45e8         mov eax, dword [var_18h]
       │           0x000011fc      83e801         sub eax, 1
       │           0x000011ff      8945f0         mov dword [var_10h], eax
       │       ┌─< 0x00001202      eb21           jmp 0x1225
       │       │   ; CODE XREF from sym.call_sys @ 0x1229(x)
       │      ┌──> 0x00001204      8b45f0         mov eax, dword [var_10h]
       │      ╎│   0x00001207      4898           cdqe
       │      ╎│   0x00001209      488d148500..   lea rdx, [rax*4]
       │      ╎│   0x00001211      488d05282e..   lea rax, obj.mints          ; 0x4040 ; U"=J`\W9J\x1a\v"
       │      ╎│   0x00001218      8b0402         mov eax, dword [rdx + rax]
       │      ╎│   0x0000121b      4898           cdqe
       │      ╎│   0x0000121d      482945f8       sub qword [string], rax
       │      ╎│   0x00001221      836df001       sub dword [var_10h], 1
       │      ╎│   ; CODE XREF from sym.call_sys @ 0x1202(x)
       │      ╎└─> 0x00001225      837df000       cmp dword [var_10h], 0
       │      └──< 0x00001229      79d9           jns 0x1204
       │           0x0000122b      b8efbeadde     mov eax, 0xdeadbeef
       │           0x00001230      483145f8       xor qword [string], rax
       │           0x00001234      488b45f8       mov rax, qword [string]
       │           0x00001238      4889c7         mov rdi, rax                ; const char *string
       │           0x0000123b      e8f0fdffff     call sym.imp.system         ; int system(const char *string)
       │           0x00001240      90             nop
       │           0x00001241      c9             leave
       └           0x00001242      c3             ret

There is a call to the libc function ``system`` near the end of this function,
at instruction ``0x123b``
However, it is hard to tell what argument is being passed to it, i.e.
what string is being pointed to. 
That is because the code has been obfuscated.

But we can use the colorizer to defeat this obfuscation  directly, via dynamic execution.
Here is a simple script to do that.

.. literalinclude:: ./c-example.py
  :language: Python

There is a bunch of boilerplate here to load the code that contains this
function as well as to model the calls to ``printf``.
That is not important.
What we want to know is what is the dynamic value in ``rdi`` when we get
to ``0x0000123b  call sym.imp.system``, and where that value came from,
if possible.
The script runs the colorizer twice.
In the first pass, we determine the color for ``rax`` at the instruction
immediately prior to the ``system`` call.
This is the value that gets copied into ``rdi``, the argument to ``system``.
In the second pass, we determine when that color was first observed,
by looking for the hint involving that color which has the message
indicating that it is a ``read-def`` (see above), meaning it
is the first observation.

.. command-output:: python3 c-example.py 2> /dev/null | egrep '(First pass|Second pass)'
    :shell:		    
    :cwd: ./

	  
The script tells us that, for this trace, the value in ``rdi`` passed to
``system`` is the same as the value in ``rdi`` at the start of the function
``call_sys``, i.e. in the instruction ``0x00001151  mov qword [var_28h], rdi``
which copies the function argument into a local variable.

Colorizer Summary Analysis
--------------------------

The ``ColorizerSummary`` analysis takes, as input, the hints generated
by the ``Colorizer``: ``DynamicRegisterValueHint`` and
``DynamicMemoryValueHint``.
That is, it registers functions to collect them.
This analysis simply normalizes colors across more than one trace.
Essentially, the first color observed becomes ``1`, and the second
becomes ``2`` etc.
Also, these are matched up across traces so the same semantic value
from two traces gets the same color.
If it is to used, the colorizer must set the ``exec_id`` correctly.
The output of this analysis is a pair of summary hints:

- DynamicRegisterValueSummaryHint
- DynamicMemoryValueSummaryHint

These are quite similar to the non-summary versions, additionally
providing

- the set of dynamic values corresponding to the same c
  olor across traces are collected.
- For the memory version of the hint, the set of addresses
  is also collected, which could be used to infer sequential
  access to array items in memory.
  
The following script shows an example use of ``ColorizerSummary`` on
the same program as above.

.. literalinclude:: ./c-example2.py
  :language: Python

In this script, the new and interesting stuff starts at line 53.
We create a ``ColorizerSummary`` analysis and register the script's
``collect_hints`` function to receive the hints that ``ColorizerSummary``
outputs.
Then, we run the colorizer five times, each time using ``randomize_uninitialized``
to get different values for registers and memory.
At this point, we run the summarizer, which has already collected
all the hints from the five colorizer runs.
It analyzes these and outputs summary hints which are, in turn,
collected, indexed by the normalized color.
The final output of interest is the hints, sorted by color, and then sorted by the program counter.

.. command-output:: python3 c-example2.py 2> /dev/null 
    :shell:		    
    :cwd: ./


If we consider just those for ``color=4`` we see the first observance of that color
is ``pc=0x1151`` in ``rdi`` and the last is ``pc=0x1238`` in ``rax``.
This is the same result as above but perhaps more nicely presented.
And it is a result that is tolerant of multiple traces.


Colorizer Write Read Analysis
-----------------------------

For those with a program analysis bent, it would seem a kind of
dynamic data-flow graph could be built from the colorizer's output.
It can, and this is the business of the ``ColorizerReadWrite`` analysis.

The nodes in this graph are instructions that were executed and which
either created or used some specific value or color.

Edges in the graph are between where a new value was first seen and
any place it was seen to be used.

Note that a new value (in the parlance of discussions above in this
tutorial, "first observation") can be *either* a read of a new value
not seen before, or by write of new, computed value.

The graph computed by the ``ColorizerReadWrite`` analysis is not exposed
as a hint.
However, a method is available that can use the graph to derive any value
in the graph, i.e., follow back-links to determine what inputs (new values)
to the graph are used to compute it.

Here is a slightly modified version of the previous script.

.. literalinclude:: ./c-example3.py
  :language: Python

Here we don't care about multiple executions, we simply want a derivation
of the value in the register ``rax`` at instruction ``0x1238``.
If we run the script...

.. command-output:: python3 c-example3.py 2> /dev/null 
    :shell:		    
    :cwd: ./

We obtain the answer directly, namely that this value is the same as what is in
``rdi`` at the start of the function.
Note that the following lines are what provide this answer:

.. literalinclude:: ./c-example3.py
  :language: Python
  :lines: 59-61
	     




	 


.. [#A] REDQUEEN: "Fuzzing with Input-to-State Correspondence", Cornelius
	Aschermann, Sergej Schumilo, Tim Blazytko, Robert Gawlik and
	Thorsten Holz, Network and Distributed Systems Security (NDSS)
 	Symposium, 2019
	
