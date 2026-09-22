.. _triton:

Triton Backend
==============

Triton is a dynamic binary analysis framework that offers concrete emulation,
symbolic execution and taint analysis over a single ``TritonContext``.
SmallWorld exposes it as two emulators: ``TritonEmulator`` for concrete
execution and ``TritonSymbolicEmulator`` for linear symbolic execution.

Triton models x86, x86-64, ARM32, AArch64 and RISC-V 64, all little-endian.
Requesting any other platform raises a ``ConfigurationError``; use
``UnicornEmulator`` or ``GhidraEmulator`` for those.

.. note::
   Using either Triton emulator requires the ``[emu-triton]`` extra, which
   pulls in JonathanSalwan's Triton (PyPI ``triton-library``, import name
   ``triton``). This is unrelated to OpenAI's ``triton`` GPU compiler.

.. caution::
   Triton's CPU models cover integer and control-flow instructions only. It has
   no floating-point semantics: x87, SSE and AArch64 FP instructions are
   reported as undefined instructions, and Triton's ARM32 target does not model
   the VFP/NEON registers at all.

Execution Control
-----------------

``TritonEmulator`` supports the standard execution control functions. Triton
exposes single-instruction stepping rather than run-to-completion, so ``run()``
drives its own fetch/decode/execute loop; ``step_block()`` runs until the next
control-flow instruction.

Because that loop is SmallWorld's rather than Triton's, ``run()`` needs at least
one exit point or execution bound before it will start, and raises a
``ConfigurationError`` otherwise.

.. note::
   Triton has no semantics for a few valid instructions, which it reports the
   same way it reports an invalid encoding. ``TritonEmulator`` recognises them
   by mnemonic and gives them their architectural meaning instead of failing:
   ``hlt`` (and the AArch64/RISC-V wait-for-event instructions) stop execution
   cleanly, and a trap instruction runs its hooks and resumes at the following
   instruction.

Exit Points and Bounds
----------------------

``TritonEmulator`` supports exit points and bounds normally.

Accessing Registers
-------------------

``TritonEmulator`` supports the registers Triton models for each architecture;
anything else raises ``UnsupportedRegisterError``. Notably absent are the x86
descriptor-table and segment-base registers, and every ARM32 register outside
Triton's small core set (r0-r12, sp, r14, pc and the flags).

Setting labels on registers has no effect on ``TritonEmulator``. On
``TritonSymbolicEmulator`` a label makes the register symbolic under that name.

Mapping Memory
--------------

Triton's own memory is flat and lazy: every address is readable, writable and
executable, and unwritten cells read back as zero. ``TritonEmulator`` therefore
keeps SmallWorld's memory map itself and enforces it, reporting an unmapped
"read", "write" or "fetch" as the other backends do. The check is per access
rather than per page.

Accessing Memory
----------------

``TritonEmulator`` supports normal memory accesses. Direct reads and writes
through the emulator API bypass the memory hooks; hooks fire only for the
accesses the emulated instructions themselves perform.

Event Handlers
--------------

``TritonEmulator`` supports the following event types:

- Instruction Hooks
- Function Models
- Memory Accesses
- System Calls
- Interrupts

Syscall hooks read the syscall number from the platform's Linux ABI register
(``rax``/``eax`` on x86, ``x8`` on AArch64, ``r7`` on ARM32, ``a7`` on RISC-V).
Where one instruction serves as both a syscall and an interrupt (``svc``,
``ecall``, ``int 0x80``), the syscall hooks get first refusal and the interrupt
hooks see whatever they do not claim.

.. note::
   Triton implements every ARM32 store as a conditional read-modify-write, so
   it reports a memory *read* of a plain ``str``/``stm``'s own destination.
   ``TritonEmulator`` suppresses those, since a store-only instruction on a
   load/store architecture never reads memory; the matching write hook still
   fires.

Symbolic Execution
------------------

``TritonSymbolicEmulator`` is a *linear* symbolic emulator, like
``GhidraSymbolicEmulator``. Triton is concolic: it maintains concrete and
symbolic state side by side and follows the one path its concrete state selects.
``enable_branching()`` therefore raises, and ``get_active_states()`` yields a
single state.

Symbolic values cross into SmallWorld's claripy world through an SMT-LIB2
string, which keeps Triton's copy of Z3 and claripy's copy from ever meeting.
Constraints are held as claripy and solved with a ``claripy.Solver``, seeded
with both user-supplied constraints and the path predicate Triton accumulates.

Symbolic memory hooks (``hook_memory_read_symbolic`` and
``hook_memory_write_symbolic``) are not implemented; Triton's memory callbacks
carry concrete values only.

Taint Analysis
--------------

Triton's taint engine is exposed through backend-specific methods rather than
the ``Emulator`` contract, since no other backend offers it:

- ``taint_register(name)`` / ``untaint_register(name)`` / ``is_register_tainted(name)``
- ``taint_memory(address, size)`` / ``untaint_memory(address, size)`` / ``is_memory_tainted(address, size)``

Taint is marked before execution and read back afterwards; Triton unions the
taint of an instruction's sources into its destination, and writing a constant
clears it.

.. caution::
   Taint propagation is only as good as the per-instruction rules in Triton's
   own semantics. Triton's RISC-V ``addi``, ``add``, ``sub`` and ``slli`` do not
   propagate their source taint, though ``or``, ``xor``, ``addiw`` and the
   load/store instructions do.

Interacting with Triton
-----------------------

.. note::
   **Understanding this section is not necessary to write a normal harness.**

   The features described here are completely abstracted
   behind the ``TritonEmulator`` interface, and are only useful
   if you want to leverage Triton for analysis.

   This section describes how to access the relevant objects,
   and any caveats regarding their access.
   Using them for analysis is an exercise left to other tutorials.

It's possible to access the ``TritonContext`` directly via the property
``TritonEmulator.ctx``. It is fully initialized once the ``TritonEmulator``
object is constructed.
