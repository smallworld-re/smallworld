.. _colorizer_tutorial:

Colorizer Analysis Tutorial
===========================

We will solve the same problem three times using, in sequence,
``Colorizer``, ``ColorizerSummary``, and ``ColorizerReadWrite``
analyses.

Take 1: Colorizer
----------------- 

The following function ``call_sym`` illustrates one way in which the
colorizer analysis can be of use.

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

There is a call to the libc function ``system`` near the end of this
function, at instruction ``0x123b`` However, it is hard to tell what
argument is being passed to it, i.e.  what string is being pointed to.
That is because the code has been obfuscated. But we can use the
``Colorizer`` to defeat this obfuscation directly, via dynamic
execution and tracking values or colors.

First, we need to harness this function. This is something you have
seen before, but here is the kind of code that will do this.

.. literalinclude:: ./c-example.py
  :language: Python
  :lines: 1-47

A few things to point out here. First, we set, as our exit point, the
call to ``system``, because we want to see the color of the value in
the argument to the call. That is, what we want to know is what is
the dynamic value in ``rdi`` when we reach ``0x0000123b call
sym.imp.system``, and to determine where that value came from, if
possible. So we can stop analyzing when we reach that call. Second,
we arrange to model the calls to ``printf`` in this function. This means
we will be able to see what they print, which might be useful, but,
more important, the harness will not fail on them since libc is not
actually available.

We will use the colorizer twice, i.e. make two dynamic analyses of the
function's code. In the first, we determine the color for ``rax`` at
the instruction immediately prior to the ``system`` call.  This is the
value that gets copied into ``rdi``, the argument to ``system``.  Here
is code that does this.

.. literalinclude:: ./c-example.py
  :language: Python
  :lines: 48-65

We register a callback ``collect_hints`` to collect hints coming from
the colorizer and then look specifically at the one that corresponds
to ``pc=0x1238`` which copies ``rax`` into ``rdi``. We save this color
into the global ``the_color``.

In a second pass use of the colorizer, we determine when ``the_color``
was first observed, by looking for the hint involving it which has the
message indicating that it is a ``read-def`` (see above), meaning it
is the first observation.

.. literalinclude:: ./c-example.py
  :language: Python
  :lines: 67-81

This is done by another callback ``collect_hints2``, which is looking
the a hint involving ``the_color`` where that color is first observed.

Note, in both passes we employ a call to ``randomize_unitialized`` to
ensure that values will get nice looking colors if not initialized
already, and we use the same seed so that the same colors will get
assigned in both and the same trace will get executed.

Here is the script in its entirety.

.. literalinclude:: ./c-example.py
  :language: Python

We can run this script to answer the question "Where does the argument
to ``system`` come from? It takes no arguments but we can filter the
output to get just the operative parts which come from the print
statements in those two hint callbacks.

.. command-output:: python3 c-example.py 2> /dev/null | egrep '(First pass|Second pass)'
    :shell:		    
    :cwd: ./
	  
The script tells us that, for this trace, the value in ``rdi`` passed to
``system`` is the same as the value in ``rdi`` at the start of the function
``call_sys``, i.e. in the instruction ``0x00001151  mov qword [var_28h], rdi``
which copies the function argument into a local variable.


Take 1: ColorizerSummary
------------------------

THIS IS NONSENSE.  YOU DONT NEED SUMMARY HERE?

We can simplify that script considerably if we use the ``ColorizerSummary``.
This script will make it easier toreason

..... Shift to using ColorizerSummary
  
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


Take 2: ColorizerReadWrite
---------------------------

We can dramatically simplify our script by making use of the
``ColorizerReadWrite`` analysis which allows us to ask derivation
questions about instructions and values.

The first part of the script, which harnesses the code to run is
unchanged. And we don't need to collect any hints, we simply run the
colorizer and arrange for its hints to be passed to a
``ColorizerReadWrite`` object which will construct a read->write graph
as described in :ref:`Colorizer Concepts <colorizer_concept>`.

.. literalinclude:: ./c-example3.py
  :language: Python
  :lines: 50-56

We can now derive where the value in ``rax`` comes from at instruction
``0x1238`` with the code

.. literalinclude:: ./c-example3.py
  :language: Python
  :lines: 58-60

The complete script looks like this:

.. literalinclude:: ./c-example3.py
  :language: Python
  :lines: 59-61

We can run this (discarding the stderr output which is considerable) with

.. command-output:: python3 c-example3.py 2> /dev/null 
    :shell:		    
    :cwd: ./

We obtain the answer directly, namely that this value is the same as
what is in ``rdi`` at the start of the function.

.. literalinclude:: ./c-example3.py
  :language: Python
  :lines: 59-61
	     

Further Reading
---------------

See the :ref:`Colorizer Concepts <colorizer_concept>` page
for more details.
