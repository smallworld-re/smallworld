.. _platforms_support:

Supported Platforms
===================

SmallWorld provides a single interface for
emulating or analyzing multiple ISAS and ABIs with multiple tools.
Sadly, not every tool is compatible with every platform. 

The following table gives a brief snapshot of our current emulation support.
The entries mean the following:

- **Yes**: The emulator supports at least the basic features of that ISA.
- **No**: The emulator does not currently support that ISA, but it's not impossible.
- **No Support**: The underlying tool does not support that ISA.

A **No** in the ``styx`` column almost always means "no SmallWorld machine
definition yet" rather than a claim about Styx itself: Styx is firmware-oriented
and each entry binds an ISA to a specific Styx target, so the arches without one
have simply not been wired up.

.. csv-table:: Basic ISA Support
    :file: basic_isa_support.csv
    :header-rows: 1
    :stub-columns: 1

Specific Emulator Notes
-----------------------

- angr is strictly a user-space emulator.  It models very few, if any, privileged features of a processor.
- Ghidra's language models are written more for static analysis than execution, so the fidelity of the various ISA models varies drastically.  Usually, they are user-space only, and may only implement approximations of certain complex instructions.
- Unicorn is a user-space emulator running on top of a full-system emulator (QEMU).  Privileged options may have unexpected effects or even crash the emulator.  Advanced users familiar with unicorn can unlock the full-system emulation features, but this is not supported directly by SmallWorld.

Specific ISA Notes
------------------

**arm32 Unicorn:** Unicorn only has one arm32 model.
It appears to support up to arm-v7 application code, 
but its privileged features are a mash-up of v6, v7, A-series, and M-series.  
Support for privileged operations is unknown.

**mips64 Panda:** The panda emulator currently runs code directly from physical memory.
In mips64, the upper half of the address space is reserved for MMIO devices.
Attempting to load state into this region will raise an exception.

**riscv64:** The RISCV64 ISA is made up of an incredibly small core feature set,
and a large number of extensions.  I can't get the assembler to build
for some of the extensions, so I haven't tested anywhere near all of them.
Also, the standards for this ISA are still being developed,
so some things like the syscall convention are something of a guess.

**SuperH:** SmallWorld models two SuperH generations, and they are not the same ISA.

*sh2a-fpu* is SH-2A-FPU. It is **big-endian only**, because the only SH-2A
language Ghidra ships is ``SuperH:BE:32:SH-2A``; there is no little-endian
equivalent, and both angr's pcode backend and Styx get their SH-2A model from
that same sleigh specification. That language is compiled with the FPU enabled,
so "SH-2A" and "SH-2A-FPU" are one and the same here.

*sh4* and *sh4el* are SH-4/SH-4A, big- and little-endian. Ghidra models these
with one language per endianness, from a specification that describes SH-4A but
is documented as working for SH-1 through SH-3 as well.

Notes per emulator:

- **Unicorn has no SuperH backend at all.** Nothing in upstream Unicorn emulates
  SuperH, so all three platforms are ``No Support`` rather than merely untested.
- **Panda** runs SuperH on a patched QEMU. QEMU upstream has an SH-4 target but
  no SH-2A model whatsoever, so SmallWorld carries a patch
  (``nix/patches/panda-qemu-sh2a.patch``) adding the SH-2A ISA - the CPU model,
  the 32-bit instruction forms, and the SH-2A-only instructions - to QEMU's
  ``target/sh4``. Two known gaps in that patch: the register-bank instructions
  ``ldbank``/``stbank``/``resbank`` decode but raise illegal-instruction, because
  QEMU has no automatic bank save on exception entry for there to interact with;
  and SH-2A's automatic bank switching on interrupt is not modelled. Neither
  matters outside interrupt-handler firmware. Being a real CPU model rather than
  a static-analysis specification, Panda is the most faithful SuperH backend
  here: it is the only one that gets SH-4 ``bsr`` and SH-2A double precision
  right.

  One operational constraint: **only one Panda emulator may exist per process.**
  QEMU registers its drive option groups into a fixed-size table at startup, so a
  second ``PandaEmulator`` in the same interpreter aborts in
  ``qemu_add_drive_opts``. This is why ``tests/unit.py`` drives the Panda
  register checks through a ``tests/unit-panda.py`` subprocess. Pairing one Panda
  with other backends in a single process is fine.

  Note also that Panda resets SH-4 with ``SR.RB`` **set**, so the architecturally
  visible R0-R7 are QEMU's ``gregs[16:24]``. SmallWorld follows the bank bits, so
  ``r0``-``r15`` always name the registers the guest is actually executing with
  and ``r0_bank``-``r7_bank`` name the inactive copies; Ghidra's SuperH4 sleigh
  does not model banking at all and behaves as though ``RB`` were 0.
- **Styx** supports SH-2A through a dedicated processor, and SH-4 through its
  generic raw processor. Styx's SH-4 architecture specification is a stub, so
  sleigh userops - ``ldtlb``, ``mac.l``/``mac.w``, the cache-block ops,
  ``trapa`` - are silently unmodelled there: the instruction steps without
  raising, but does nothing. Prefer Ghidra or Panda for SH-4 work that needs
  those. Styx also hangs rather than faulting if a SmallWorld hook is installed
  and the processor is then single-stepped, so hook-based scenarios skip it.

**⚠ ``bclr #imm3,Rn`` corrupts memory on angr and Styx.** The two bundled copies
of Ghidra's SH-2A specification are not identical, and this is their only
difference. Ghidra 12.1.2 implements the register form correctly as
``rn = rn & ~(1 << imm)``; the copies shipped in pypcode 3.3.3 and Styx instead
carry ``local b = *:1(rn); *:1(rn) = b & ~(1 << imm)`` - the semantics of the
*memory* form ``bclr.b #imm3,@(disp,Rn)`` applied to the register form. So the
register is left unmodified and a byte of memory at the address held in ``Rn`` is
rewritten instead. Because that spurious access generally succeeds (angr's memory
is lazily symbolic; Styx maps a flat 4 GiB), it corrupts memory silently rather
than faulting. Only the Ghidra backend gets this instruction right.

**⚠ angr writes zero for 16-bit stores on SuperH.** ``mov.w Rm,@Rn`` stores zero
instead of the low half of ``Rm``; the load side and the 32-bit stores are
correct. Both the plain ``@Rn`` form and SH-2A's displaced 32-bit form are
affected, and since the bundled specifications differ only in ``bclr`` this is
not a specification defect.

**⚠ SH-4 calls do not set PR under angr or Ghidra.** This is a defect in Ghidra's
SuperH4 sleigh specification, not in SmallWorld, and it affects both backends
that derive from it. In ``SuperH4.sinc``, ``:bsr`` - the ordinary PC-relative
call - performs its ``delayslot(1); call ...`` with no assignment to ``PR`` at
all, so the return address is simply never recorded. ``:bsrf`` and ``:jsr`` do
assign ``PR``, but to ``inst_next`` (the delay-slot instruction) rather than the
architectural ``inst_start + 4`` (past it). Ghidra's separate SH-2A
specification gets all three correct, so *sh2a-fpu is unaffected*, and Panda
runs on real QEMU and is also unaffected. Consequences for SH-4 on angr and
Ghidra: any harness relying on call-and-return through ``bsr`` will read a stale
or zero ``pr``. Test scenarios that depend on it (``call``, ``strlen``) are
skipped for ``sh4``/``sh4el`` on those two engines. Use Panda, or ``jsr @Rn``
with a two-byte correction, if you need calls on SH-4.

**SuperH delay slots:** every SuperH control transfer except the SH-2A ``/n``
forms executes the following instruction *before* branching. Hand-written SuperH
assembly that was ported from another architecture without accounting for this
will compute the wrong answer silently rather than failing. The SH-2A ``rts/n``,
``rtv/n`` and ``jsr/n`` instructions exist specifically to branch *without* a
delay slot. Under both pcode backends the delay-slot instruction is folded into
the branch's own translation, so a single step over ``rts`` also executes its
delay slot; Panda steps the two separately.

For the *conditional* delayed branches ``bt/s`` and ``bf/s``, the delay-slot
instruction executes **unconditionally** - only the branch itself is conditional.
The Renesas pseudocode is easy to misread as suppressing the delay slot when the
branch is not taken, but QEMU (``cpu_delayed_cond`` plus
``TB_FLAG_DELAY_SLOT_COND``, with the delay slot decoded normally in between) and
Ghidra's sleigh (``local cond = T; delayslot(1); if (cond) goto ...``) implement
it the same way, independently.

**SuperH register aliases:** SuperH returns through the PR register rather than a
general-purpose one, so SmallWorld exposes ``pr`` under the additional names
``ra`` and ``lr``. Likewise ``sp`` aliases ``r15`` and ``fp`` aliases ``r14``.
The double-precision registers are the parents of the single-precision ones -
``drN`` is composed of ``frN`` (upper half) and ``frN+1`` (lower half) - so
writing ``dr0`` changes ``fr0`` and ``fr1``, in both endiannesses.

**xtensa:** The Xtensa ISA is made up of a core feature set, a number of open ISA options,
and some proprietary extensions introduced by the manufacturer.
Our emulation support depends on Ghidra's hardware model,
which only handles part of the open ISA options.  
In particular, it does not handle all options and extensions used by the esp32 series of SoCs.
You will run into untranslatable instruction errors.

**Register Windows:** Some ISAs - SPARC64 and some Xtensa variants -
save and restore call frames by changing how the general purpose registers alias the register file.  
Compare this to how most other architectures push and pop registers from the stack.  
Windowed architectures are impossible to emulate in a userspace-only emulator, 
since they use interrupts to "spill" registers onto the stack if there are more call frames 
than they have windows.  Currently, only angr and ghidra support the relevant ISAs;
until that changes, SmallWorld cannot support windowed ISAs.

Floating Point and Vector Support
---------------------------------

Support for specific scalar and vector 
floating point subsystems is much more variable, and largely untested.

The following table lists our current support for known subsystems.
"Support" means that a) the underlying emulator can emulate the instructions,
and b) that we can interact with the relevant machine state through SmallWorld. 
The entries mean the following:

- **Yes:** The emulator has tested support for this subsystem.
- **Untested:** The emulator exposes the right state, but the system is untested
- **No**: The emulator does not currently support this subsystem.
- **No Support:** The underlying tool doesn't support this subsytem

.. csv-table:: Basic ISA Support
    :file: float_support.csv
    :header-rows: 1
    :stub-columns: 1

A few notes:

- SmallWorld's State interface doesn't have special handling for floating-point registers.  Encoding and decoding the floating point format is currently up to the user. 
- Panda can probably emulate many of these, but it needs to be modified to expose the FPU registers.
- Unicorn looks like it supports the mips32 FPU.  No one I've found has gotten it to work.
- **angr cannot do floating point on any Pcode-backed architecture.** In
  ``angr/engines/pcode/behavior.py`` every ``OpBehaviorFloat*`` class - add,
  subtract, multiply, divide, square root, the comparisons, the conversions -
  has its body present only as commented-out C++ that was never ported to
  Python, so the base class raises ``AngrError("Not implemented!")``. This is why
  the ``angr`` column reads **No** for SuperH, and it applies equally to every
  other Pcode-backed ISA here: TriCore, Xtensa, MSP430 and LoongArch. The angr
  entries that do work are all VEX architectures.
- **SuperH double precision** is a separate row from single because the two are
  selected at runtime by ``FPSCR.PR`` rather than by the opcode, and the backends
  differ in two distinct ways.

  On **SH-2A** the sleigh model simply does not implement it: ``superh.sinc``
  defines ``@define FP_PR "fpscr[19,1]"`` and then never references it again, so
  ``:fadd`` and friends are unconditionally single-precision operations on the
  4-byte registers. A double-precision operation therefore performs
  single-precision arithmetic on the **upper 32 bits** of its operands and
  zeroes the low half - ``1.5 + 2.25`` comes back as ``480.0``, which is exactly
  ``f32(1.9375 + 2.03125)`` sitting in a double's high half. Every backend
  bundling that specification inherits it, so Ghidra and Styx agree on the wrong
  answer; Panda, running real QEMU, is the only backend that gets SH-2A double
  precision right.

  On **SH-4** the specification *does* implement double precision, branching on
  the standalone one-byte ``FPSCR_PR`` register. But that register is only
  updated by sleigh's ``splitFPSCRregister()`` macro, which runs inside the
  ``lds Rm,FPSCR`` instruction - so guest code that sets ``FPSCR`` the normal way
  gets correct double-precision arithmetic, while a harness that writes the
  ``fpscr`` register directly leaves ``FPSCR_PR`` stale and silently gets the
  single-precision path. The same caveat applies to ``SR`` on SH-4, whose T, S, M
  and Q bits live in separate sleigh registers refreshed only by
  ``splitSRregister()``. Panda has no such split and honours a direct write.

Floating-point conformance testing
----------------------------------

The ``testfloat`` scenario checks FPU arithmetic against `Berkeley TestFloat
<http://www.jhauser.us/arithmetic/TestFloat.html>`_ rather than against
hand-written expectations. TestFloat's ``testfloat_gen`` emits operand sets
chosen to sit on the hard boundaries - subnormals, the largest and smallest
normals, values one ULP either side of a rounding boundary - and
``testfloat_ver`` re-derives the reference from the operands with Berkeley
SoftFloat and reports every disagreement. Feeding it a whole run at once means
each function is checked over thousands of adversarial cases instead of a
handful of round numbers.

TestFloat's source is **not vendored**. ``nix/testfloat.nix`` fetches
SoftFloat-3e and TestFloat-3e by URL with pinned SRI hashes and builds them for
``Linux-x86_64-GCC``; ``runtimeToolsFor`` in ``nix/runtime-support.nix`` puts
``testfloat_gen`` and ``testfloat_ver`` on the test shell's ``PATH`` on Linux.
The reference is built with ``SPECIALIZE_TYPE=8086-SSE``.

Each architecture supplies one assembly file containing four loop kernels - one
per (precision, arity) - at fixed offsets, sharing one exit label. The harness
picks an entry point, patches the single arithmetic instruction in place, and
lets the guest walk an array. The contract is the same everywhere: ``r4`` is the
input cursor, ``r5`` the output cursor, ``r6`` the case count, and on SuperH
``r7`` carries the FPSCR value that the kernel installs with ``lds`` - a direct
register write would leave the split ``FPSCR_PR`` stale, as described above. A
memory loop is used rather than one instruction stepped per case because Panda
turns every second ``step_instruction()`` after a ``pc`` rewrite into a no-op.
Because the kernels are ordinary scenario assembly, the existing pattern rules
build them and no ``tests/Makefile`` changes were required.

Two things are deliberately **not** compared:

- **Exception flags.** The kernels do not read FPSCR back per case, so there is
  nothing to compare against TestFloat's five-flag model; SuperH also splits its
  exception state into separate Cause and Flag fields that do not map onto it
  one-for-one. Only result values are checked, which the run banner states
  explicitly.
- **NaN payloads.** IEEE 754 does not specify them, and SuperH deliberately does
  not propagate them - every NaN-producing operation returns the fixed qNaN
  ``0x7FBFFFFF`` - whereas the ``8086-SSE`` reference propagates an input
  payload. Comparing these would fail Panda, the backend that models the
  hardware most faithfully, while passing backends that happen to match x86.
  Since ``testfloat_ver`` re-derives the reference rather than reading it from
  the file, the payload cannot be normalised in place, so cases whose *reference
  result* is a NaN are dropped before comparison and the count is reported on
  each line.

Measured results, 2000 generated cases per function. The five functions per
precision are add, subtract, multiply, divide and square root.

.. csv-table:: TestFloat results
    :file: testfloat_results.csv
    :header-rows: 1
    :stub-columns: 1

Little-endian SuperH (``sh4el``) matches big-endian ``sh4`` in every cell.

Every skip is an upstream defect, reduced to a minimal case first:

- **angr** is skipped wholesale - it implements no floating point on any
  Pcode-backed architecture, as described above.
- **SH-2A double precision** is skipped on the sleigh-derived backends because
  ``superh.sinc`` ignores ``FPSCR.PR``. TestFloat measures this precisely:
  ``0.0 + A57F319EDE38F755`` returns ``0x3FF0000000000000`` for a preceding
  ``1.0``, because with ``SZ`` ignored too the kernel loads four bytes into
  ``fr0``, four into ``fr2``, adds single-precision and stores four.
- **Single-precision multiply and divide** are skipped under ``ghidra`` because
  Ghidra's p-code emulator flushes gradual-underflow results to zero:
  ``0x00000001`` (the least positive subnormal) times ``0x3F000001`` yields
  ``0x00000000`` where the reference is ``0x00000001`` with underflow and
  inexact set. Every mismatch found had that shape. This is not the SuperH
  specification - Styx executes the *same* sleigh through its own p-code engine
  and passes all five single-precision functions - so the defect is in Ghidra's
  float evaluation and is not specific to SuperH. Double precision is
  unaffected.

Panda passes all ten functions on all three SuperH platforms, which is the
strongest available evidence that the SH-2A instruction set added to QEMU in
``nix/patches/panda-qemu-sh2a.patch`` computes correctly and not merely
plausibly.

Two notes for anyone extending this scenario to another architecture. The patch
tables spell opcodes most-significant-byte-first the way the ISA manual does, so
they are byte-swapped before being written into a little-endian image; getting
this wrong turns ``fadd`` into an unrelated instruction. And a double-precision
register pair must name an even register - an odd field is an illegal
instruction on hardware, while Ghidra's sleigh quietly substitutes the even
register below it and produces confident ``a op a`` arithmetic. The
``--check-patches`` flag disassembles every patch-table entry, operands
included, to keep both mistakes visible.

