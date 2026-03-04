.. _trace_execution_tutorial:

TraceExecution Analysis Tutorial
================================

Consider the following situation.
After some manual reverse engineering of some malware, you have become
interested in a function that takes an integer as input and returns an
integer which is tested against the value 1 to decide a branch.
You suspect the code in one of the branches to be nonsense filler
that might never execute; this is a common techinque, in which malware is
augmented with *opaque predicates* that always evaluate one way and
garbage filler code is injected into the other branch to waste the
time of a reverse engineer.
You are curious to understand how this function operates and you see that
it works in a loop, computing the return value iteratively.
A value derived from that computed value is tested against 24 in order
decide when to exit the loop.
The value returned by the function is tested against 1 in what you
expect is the opaque predicate.
That is, you think this function always returns 1. 

Here is that function ``coll``, rendered by radare.

.. code-block::

   ┌ 114: sym.coll (int64_t arg1);
   │ `- args(rdi) vars(5:sp[0xc..0x1c])
   │           0x00001149      55             push rbp
   │           0x0000114a      4889e5         mov rbp, rsp
   │           0x0000114d      897dec         mov dword [var_14h], edi    ; arg1
   │           0x00001150      c745fc0000..   mov dword [var_4h], 0
   │           ; CODE XREF from sym.coll @ 0x11a6(x)
   │       ┌─> 0x00001157      8b45ec         mov eax, dword [var_14h]
   │       ╎   0x0000115a      83e001         and eax, 1
   │       ╎   0x0000115d      85c0           test eax, eax
   │      ┌──< 0x0000115f      7511           jne 0x1172
   │      │╎   0x00001161      8b45ec         mov eax, dword [var_14h]
   │      │╎   0x00001164      89c2           mov edx, eax
   │      │╎   0x00001166      c1ea1f         shr edx, 0x1f
   │      │╎   0x00001169      01d0           add eax, edx
   │      │╎   0x0000116b      d1f8           sar eax, 1
   │      │╎   0x0000116d      8945ec         mov dword [var_14h], eax
   │     ┌───< 0x00001170      eb0f           jmp 0x1181
   │     ││╎   ; CODE XREF from sym.coll @ 0x115f(x)
   │     │└──> 0x00001172      8b55ec         mov edx, dword [var_14h]
   │     │ ╎   0x00001175      89d0           mov eax, edx
   │     │ ╎   0x00001177      01c0           add eax, eax
   │     │ ╎   0x00001179      01d0           add eax, edx
   │     │ ╎   0x0000117b      83c001         add eax, 1
   │     │ ╎   0x0000117e      8945ec         mov dword [var_14h], eax
   │     │ ╎   ; CODE XREF from sym.coll @ 0x1170(x)
   │     └───> 0x00001181      8345fc01       add dword [var_4h], 1
   │       ╎   0x00001185      8b45ec         mov eax, dword [var_14h]
   │       ╎   0x00001188      8d5001         lea edx, [rax + 1]
   │       ╎   0x0000118b      8b45ec         mov eax, dword [var_14h]
   │       ╎   0x0000118e      83c002         add eax, 2
   │       ╎   0x00001191      0fafc2         imul eax, edx
   │       ╎   0x00001194      8b55ec         mov edx, dword [var_14h]
   │       ╎   0x00001197      83c203         add edx, 3
   │       ╎   0x0000119a      0fafc2         imul eax, edx
   │       ╎   0x0000119d      8945f8         mov dword [var_8h], eax
   │       ╎   0x000011a0      837df818       cmp dword [var_8h], 0x18
   │      ┌──< 0x000011a4      7402           je 0x11a8
   │      │└─< 0x000011a6      ebaf           jmp 0x1157
   │      │    ; CODE XREF from sym.coll @ 0x11a4(x)
   │      └──> 0x000011a8      90             nop
   │           0x000011a9      8b45ec         mov eax, dword [var_14h]
   │           0x000011ac      8945f0         mov dword [var_10h], eax
   │           0x000011af      8b45fc         mov eax, dword [var_4h]
   │           0x000011b2      8945f4         mov dword [var_ch], eax
   │           0x000011b5      488b45f0       mov rax, qword [var_10h]
   │           0x000011b9      5d             pop rbp
   └           0x000011ba      c3             ret
   [0x00001060]> 

One way to understand better what this function is doing is to harness
it with SmallWorld so that you can instrument it to inspect values
inside that computation loop (the instruction ``0x11a4 jmp 0x1157``).
Then, you can run the code for various input and peek into how it is
doing its computation.

To harness this code you will need a bit of boilerplate-is stuff that
you have seen before in other examples and tutorials.  This includes
import smallworld, creating an ``X86_64`` cpu, loading the code which
is in an ELF file ``te-example``, and specifying the entry and exit
points in a machine.  Here is that code:

.. literalinclude:: ./te-example.py
  :language: Python
  :lines: 1-26

After that, with a little RE, it is obvious that this function needs a
stack and that it takes a single argument ``rdi`` which is used as an
integer in some compuation.  These two facts give us these additional
lines in our harness, in which the script's single command-line
argument is fed into ``rdi`` as an input.

.. literalinclude:: ./te-example.py
  :language: Python
  :lines: 27-34

You'll also need to have something to inspect and a place to look at
that value. From manual RE, the value in ``eax`` at program counter
``0x1185`` seems interesting. First, because it is also the value
returned by the function when we exit the loop. Second, because it is
used at the top of the loop (see the instruction at ``0x1157``) as the
start of a per-loop computation.

It would be interesting to be able to run this function with various
inputs and see the value in ``eax`` at program counter ``0x1185``
inside the loop. You can achieve that, easily, with the before/after
instruction execution callbacks in the ``TraceExecution`` analysis.
Note that more details are provided about that in the
:ref:`TraceAnalysis concepts section<trace_execution_concept>`.

First, set up a hinter, wire it up to a ``TraceExecution``
analysis object, and register a function to be called before
every instruction executes as follows.

.. literalinclude:: ./te-example.py
  :language: Python
  :lines: 36-42

The function simply prints out the value of ``eax`` if the program
counter is ``0x1185``.

The final line of the script runs the analysis which generates a
single trace given the value for ``rdi``.

.. literalinclude:: ./te-example.py
  :language: Python
  :lines: 44

Note that, in the constructor for the ``TraceExecution`` analysis, a
bound is set on the number of instructions that will execute.
Here, 10000 will be enough.

The complete script looks like this.

.. literalinclude:: ./te-example.py
  :language: Python
    
You can use this script to try out various inputs to the function.
For example, if you wanted to try 7, you would type ``python
te-example 7``.  Here is the output for inputs of 1 through 6.

.. command-output:: python3 te-example.py 1
    :cwd: ./

.. command-output:: python3 te-example.py 2
    :cwd: ./

.. command-output:: python3 te-example.py 3
    :cwd: ./

.. command-output:: python3 te-example.py 4
    :cwd: ./

.. command-output:: python3 te-example.py 5
    :cwd: ./

.. command-output:: python3 te-example.py 6
    :cwd: ./

This output might begin to ring bells.  If not, you can try googling
the sequence for 6, which is ``6, 3, 10, 5, 16, 8, 4, 2, 1`` .  This
is the *hailstone* sequence, which seems always to end in 1 but this
has never been proved (this is known to math people as the Collatz
conjecture).  See the `Wikipedia page on the Collatz conjecture
<https://en.wikipedia.org/wiki/Collatz_conjecture>`_ for more info.

Truly, this does appear to be a weird kind of opaque predicate.


Further Reading
---------------

See the :ref:`TraceExecution Concepts <trace_execution_concept>` page
for more details.
