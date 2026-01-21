Trace Execution Analysis
========================

The TraceExecution class provides a convenient way to capture
a single execution trace for some code.
Given an initial machine state passed to the ``run`` method, the Unicorn
emulator is used to single step one instruction at a time through the
code until doing so raises an exception.

Two known exceptions are caught when single-stepping:
``EmulationBounds`` and ``EmulationExitPoint``.
These  both indicate the emulator should
not continue, as it has finished executing the required code (and
is about to walk off into other or missing code).
Other possible exceptions of interest are subclasses of ``EmulationError``
and are listed and explained in
``smallworld.exceptions`` and include invalid read/write of memory
(typically due to an address being unmapped).
The exception which ended the trace is diagnostic and is saved to be
added to the hint output by this analysis (more details below).

For each instruction, a ``TraceElement`` object is constructed consisting
of instruction address and mnemonics as well as details about branch
and comparison instructions (for matching instructions).
These ``TraceElement`` objects are collected in a list which represents
the trace.
This list and other information are bundled into the ``TraceExecutionHint``,
along with the exception that was thrown to end the trace.
This hint is the main output of this analysis.
There are more details below.

This analysis can be used to build other analyses by registering functions
to be run before and after an instruction executes.
This is done with ``TraceExecution.register_cb(cb_point, cb_function)``.
An example is provided below.
For a much more detailed worked example, you can study how the ``Colorizer``
analysis works, which employs these callbacks.  


Example Use
-----------

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

Here is that function

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


You decide to use SmallWorld to harness just this function and peek
into the loop to see what the computed value is for each iteration
of the loop, as this sequence might be revelatory.
From manual RE you determine that a good place to spy on the
per-loop-iteration computed value is ``0x1185``, where the value is
in the register ``eax``.

Here is the script you write to accomplish this.

.. literalinclude:: ./te-example.py
  :language: Python

The script contains nothing new until after setting ``rdi`` the single
argument to this function to be the only argument to the script.

The script uses the  ``TraceExecution`` analysis because that provides
an easy way to run code before every instruction.
That code is in the function ``before_cb``, which simply collects the
values of ``eax`` into an array.
This callback is registered to run via the following line.

.. code-block:: python3

    ta.register_cb(TraceExecutionCBPoint.BEFORE_INSTRUCTION, before_cb)

Note that, in the constructor for the ``TraceExecution`` analysis, we
can set a bound on the number of instructions that will execute.
In this case it is 10000:

.. code-block:: python3

    ta = TraceExecution(hinter, num_insns=10000)
    
We can use this script to try out various inputs to the function.
For example, if we wanted to try 7, we would type ``python te-example 7``.
Here is the output for inputs of 1 through 6.

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

The output might begin to ring bells.
If not, you can try googling the sequence for 6, which is
``6, 3, 10, 5, 16, 8, 4, 2, 1`` .
This is the *hailstone* sequence, which seems always to end in 1 but this has
never been proved (this is known to math people as the Collatz conjecture).
See the `Wikipedia page on the Collatz conjecture <https://en.wikipedia.org/wiki/Collatz_conjecture>`_ for more info.

Truly, this does appear to be a weird kind of opaque predicate.

The TraceExecutionHint
----------------------

Calbacks can be useful, but another way to use the ``TraceExecution``
analysis is to collect and examine the ``TraceExecutionHint`` that it
outputs.
This collection can happen in some other analysis that uses the
information in that hint, or can happen directly in our top-level
smallworld script.
Here is a slightly augmented version of the script we have been using which
contains code to collect and examine this hint.

.. literalinclude:: ./te-example2.py
  :language: Python

It is this part of the code that collects and outputs the trace portion of the hint:

.. code-block:: python3

     def collect_hints(h):
	 for te in h.trace:
	     print(te)

     ...
     hinter.register(smallworld.hinting.TraceExecutionHint, collect_hints)

If you run this script you will see an execution trace before the hailstones sequence output.

.. command-output:: python3 te-example2.py 6
    :cwd: ./

     
The ``TraceExecutionHint`` has the following structure

.. code-block:: python3

     @dataclass(frozen=True)
     class TraceExecutionHint(TypeHint):
         trace: typing.List[TraceElement]
         trace_digest: str
         seed: int
         emu_result: TraceRes
         exception: typing.Optional[Exception]
         exception_class: str

The ``trace_digest`` is an md5 sum that will be different for different
sequences of program counters.
The ``seed`` is a value that can be set to indicate the PRNG seed to use
to reproduce this trace, given various random choices made in setting up
the environment.
``emu_results`` is used to indicate how the trace ended:

.. code-block:: python3

    class TraceRes(Enum):
        ER_NONE = 0
        ER_BOUNDS = 1      # hit execution bound or exit point
        ER_MAX_INSNS = 2   # hit max number of instructions
        ER_FAIL = 3        # some kind of emulation failure

The actual exception that ended the trace is also stored in the ``exception`` member.
	 
The ``trace`` member is what we saw as output above, which is a list of
``TraceElement`` objects, one for each instruction executed.
These have the following structure.

.. code-block:: python3

     @dataclass
     class TraceElement:
         pc: int
         ic: int  # instruction count
         mnemonic: str
         op_str: str
         cmp: typing.List[CmpInfo]
         branch: bool
         immediates: typing.List[int]

