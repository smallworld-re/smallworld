.. _analyses_crash_triage:

Crash Triage Analysis
=====================

SmallWorld provides a simple analysis for diagnosing crashes in harnessed code.

Concrete emulators like Unicorn are great at identifying crashes,
but diagnosing exactly why the crash happened is a pain;
by the time you encounter a NULL pointer,
you've lost the context necessary to figure out
how that NULL got into that operand.

Taxonomy of Crashes in SmallWorld
---------------------------------

Before we can diagnose a crash,
we need to define when a crash actually happens.

Not Reproducible
****************

The program exited in a way this analysis considers "normal".
The harness provided does not cause a crash,
at least not deterministically.

- Program exited normally via ``exit()`` or something similar
- Program counter hit an exit point
- Program tried to execute a modeled function marked as unsupported or imprecise
- Emulation exceeded a specified number of steps

Out of Bounds Execution
***********************

The program went outside of some definition of execution bounds.

- Program counter went outside execution bounds
- Program counter went outside mapped memory
- Program counter was determined from uninitialized data

The choice to treat execution bounds and exit points separately
differs from standard SmallWorld harness semantics.

Illegal Operation
*****************

The program tried to execute an instruction that's deemed illegal by the platform

- Program tried to execute garbage bytes
- Program tried to execute a valid instruction that is always illegal, like x86's ``ud2``
- Program tried to execute a valid instruction with malformed operands
- Program tried to execute a valid instruction in an invalid context
- Program tried to execute a valid instruction unsupported by the emulator

Memory Error
************

The program tried to perform an illegal memory access

SmallWorld recognizes three kinds of memory accesses

- Data read
- Data write
- Instruction fetch

Each of these can fail for one of the following reasons:

- Memory accessed was outside the memory map
- Memory accessed did not permit that kind of access
- Address accessed violated the alignment rules for the operation
- Address accessed was determined from uninitialized data

Note that "fetch" errors overlap with out of bounds execution errors;
exactly which kind of crash will get reported depends on the platform.
This is further complicated by the fact that not all platforms
have separate concepts of "read" and "fetch",
so interpreting a crash will require some platform-specific knowledge.

Hardware Exception
******************

The program encountered a hardware exception other than
a memory error or illegal operation.

Any further distinction will depend on both the platform,
and on the emulator implementation. 

Data Tracing by Symbolic Execution
----------------------------------

Much of the previous taxonomy can be readily detected with concrete emulation.
There are two big limitations:

1. Concrete emulators can't easily distinguish uninitialized values from initialized ones.
2. Concrete emulators can't easily trace data back to the initial machine state from whence it's computed.

What we need is a kind of high-precision data flow analysis
that can express values relevant to a crash in terms of initial machine state.
It turns out SmallWorld already has one, in the form of angr.

A symbolic executor represents data in bit vector logic.
Values are fixed-width bit strings that can be concrete values,
named variables, or arbitrarily complicated expressions combining
values and variables.

The primary reason for using this representation is to
allow the executor to explore multiple program paths;
if faced with a conditional branch, it can test
whether each branch could be possible,
then create a separate path for each possible branch,
constraining the conditional to be true or false
depending on which branch is being explored.

A side-effect of this system is that a value computed from named variables
will be an expression in terms of those variables.

Consider the following amd64 code snippet:

.. code-block:: nasm

    mov rax,rdi
    add rax,rsi

If you assign ``rdi`` to be a 64-bit variable named ``arg1``,
and ``rsi`` to be a 64-bit variable named ``arg2``,
executing these two instructions will give ``rax`` the value ``<BV64 arg1 + arg2>``,
that is, a 64-bit expression representing the sum of ``arg1`` and ``arg2``.
Not only can you tell the origin of the data,
you can also tell how it was used to compute the final value.

Additionally, the constraint mechanism used to guide path exploration
can be used to bind variables to specific values.
If you bind ``arg1`` and ``arg2`` to 64-bit values representing the integer "2",
the expression ``<BV64 arg1 + arg2>`` will always behave as the integer "4".

Combined, this makes single-path symbolic execution an extremely powerful analysis tool. 
It allows us to add labels to the concrete parts of an initial machine state,
and to watch how those labels propagate as the program executes.

It also gives us a very clear indication of when a program is using uninitialized machine state.
Uninitialized registers and memory regions are initialized with default variables by angr.
These can be used by a post-mortem analysis to identify values computed from uninitialized data,
plus SmallWorld's angr backend can be configured to halt if it tries
to jump to an unconstrained program counter, 
dereferences an unconstrained memory address,
or encounters a conditional branch
where the guard expression depends on uninitialized data.

Diagnosing Crashes
------------------

The key limitation with angr is that it's not really great at detecting many kinds of crashes.
For one, it just doesn't model as much of the hardware as Unicorn or Panda.
For two, several features that facilitate exploring under-constrained program paths
make it difficult to identify certain kinds of errors.

Thus, SmallWorld's crash triage analysis uses both Unicorn and angr
in tandem to diagnose crashes:

1. Label all machine state that was not already labeled by the harness author.
   Assign default labels to registers and memory based on their names/addresses.
2. Run the harness through Unicorn to see if it produces a crash.
   Remember the exection trace, or sequence of instructions taken by Unicorn.
   Also remember any details from the crash, such as offending operands for memory errors.
3. If a crash actually happened, re-run the harness through angr up to the point before the failing instruction.
4. If angr exited early or did not follow the trace, report that finding.
5. If angr reaches the crashing instruction, perform a crash-specific analysis to try and diagnose.

This process will generate a single hint that's a subclass of ``TriageHint``.
The exact type of the hint matches the failure case detected by Unicorn.

Each hint will include a ``Diagnosis`` object,
which will either be a ``DiagnosisEarly`` object detailing
why angr didn't successfully reproduce the trace from Unicorn,
or a crash-specific diagnosis.

Early Termination
*****************

It's very possible that angr will not duplicate the same execution trace as Unicorn.

- The program counter at a particular step was different between Unicorn and angr
- The prorgam encountered an instruction angr couldn't emulate
- The program encountered an unconstrained conditional branch
- The program tried to dereference an unconstrained address

Early crashes due to illegal instructions are expected.
angr's symbolic executor is based on either Vex (Valgrind's IR),
or Pcode (Ghidra's low-level IR).
Both are very aggressively user-space focused,
and will not support the same set of operations as Unicorn's QEMU backend.

Unconstrained dereferences and conditional branches are the most interesting;
they indicate that the program path to the crash
was only reached thanks to uninitialized machine state,
almost certainly meaning the harness was incomplete.

Diagnosing Out of Bounds
************************

All forms of out-of-bounds execution can be detected
by examining the program counter of the state reached
after replaying the trace through angr.

First, test if there is a single possible evaluation
for the program counter.  If not, it depends on uninitialized data,
which is almost certainly why we saw out-of-bounds execution in Unicorn.
See "Diagnosing Unconstrained Expressions" below for more details.

If it does evaluate to a single concrete value,
test it against the program bounds and memory map.
If it's outside some notion of execution bounds,
then we can confirm the report we got from Unicorn.

Confirmed out-of-bounds execution hints will include a ``DiagnosisOOBConfirmed``
object, containing a ``Halt`` object describing why emulation halted.

If it is concrete and is in bounds, something odd is happening.
Report that we're unable to confirm the failure
by including a ``DiagnosisOOBUnconfirmed`` object in the hint.

Diagnosing Illegal Instructions
*******************************

Diagnosing illegal instructions is tricky,
since we're dealing with three separate definitions of what makes
an instruction legal or illegal:

- Unicorn's execution engine
- angr's program lifter (Vex or Pcode)
- Whatever disassembler is exposed by angr

None of these three definitions are perfectly accurate to real hardware,
so we need to make some best-guess approximations.

These details are captured in subclasses of ``IllegalInstr``,
which is used by both ``DiagnosisIllegal``
when Unicorn detects an illegal instruction,
and ``DiagnosisEarlyIllegal`` when angr terminates early
due to an illegal instruction.

The first check is whether the instruction is decodable.
For this, the analysis uses the disassembler.
If it can't disassemble the instruction at all,
then we assume this is gibberish,
and report ``IllegalInstrNoDecode``.

The second check is whether angr can lift
the instruction into something sensical.
Both emulators indicate a decoding failure
using the control flow type ``Ijk_NoDecode``.
If we see an ``IjkNoDecode`` edge at the end of the lifted IR,
we know that angr considers the instruction illegal,
and report ``IllegalInstrConfirmed``.
Otherwise, we report ``IllegalInstrUnconfirmed``.

Using the lifter isn't precise, since Vex isn't always consistent
in labeling illegal instructions with ``Ijk_NoDecode``.

Diagnosing Memory Errors
************************

Diagnosing memory failures precisely parallels diagnosing an out-of-bounds execution.
Instead of examining the program counter at the state,
we look at the invalid operands reported by Unicorn's error handler.

We assume that each of them might evaluate to a memory address,
and check for the following conditions:

- The operand is constrained to a single value, and falls within the memory map
- The operand is constrained to a single value, and falls outside the memory map
- The operand evaluates to more than one value, and is unconstrained
- The operand evaluates to no values, and is unsatisfiable given the current path constraints

These are collected into a ``DiagnosisMemory`` object.
Safe and unmapped operands are reported along with their expression,
and the concrete value they represent.
Unconstrained and unsatisfiable arguments are just reported with the details of the expression.

See "Diagnosing Unconstrained Expressions" for details.

Diagnosing Unconstrained Expressions
************************************

When presented with an expression responsible for a fault, usually a memory address,
we want to be able to tell what parts of initial machine state contributed to that value.

This relies on the first step of labeling all initial machine state.
We can recognize three kinds of labels:

- Semantic labels provided by the harness author
- Generated labels for initialized registers and memory
- Generated labels for uninitialized registers and memory

Any value built up from initial machine state will be an expression
in terms of these variables, allowing us to identify
places where the original harness was either incomplete or incorrect.

Harness authors can also explicitly initialize certain values as "symbolic";
they have a label, but no initial value.
This will cause the analysis to report if the program tries to use that value.

All of this is captured in an ``Expression`` object
used by several of the hint and diagnosis classes.
It includes the raw Claripy expression being examined,
an analysis of the portions of the harness that contributed to it,
and, for simpler values, the precise memory region it represents.

Note one key limitation: It's not feasible to label executable memory.
Using data from labeled memory requires evaluating it through angr's solver.
This is fine when dealing with register-sized pieces of data,
but angr's lifter will try to concretize up to a page of memory
when building a basic block.
In practice, this slows execution down from about fifty instructions per second,
to less than one instruction per second.

Diagnosing Traps
****************

Diagnosing traps other than illegal instruction
and memory failures is currently unsupported.

Each platform has its own set of traps,
and the details of when a particular instruction
could raise a particular trap are entirely
implementation-specific.  Consider integer divide-by-zero:

- amd64 and i386 raise a specific "div0" exception
- aarch64, armel, and armhf do not raise any exception; x divided by zero equals zero
- The mips variants raise a generic "trap" exception that's indistinguishable from an illegal instruction

Further more, Unicorn is incredibly inconsistent
in how it handles and reports traps.

For now, the analysis just confirms that
it reaches the correct instruction.
