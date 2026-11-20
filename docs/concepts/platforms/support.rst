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

**la32:** 32-bit LoongArch, on Ghidra and angr. Both run Ghidra's
``Loongarch:LE:32:ilp32d`` language, the one with the double-precision FPU's
8-byte registers; angr runs it through its p-code engine, as pypcode ships it.
ilp32f and soft-float binaries run on it too, but floating-point arithmetic
only runs on Ghidra: angr has no p-code floating point (see the floating-point
notes below), so on angr only soft-float code and FPR moves work. Unicorn,
PANDA and Capstone have no LoongArch32 support, and SmallWorld has no Styx
machine definition for it.

That language is not either published LoongArch32 variant. It is
LoongArch64's base instruction set without the 64-bit-wide operations, so it
decodes LA32R (reduced) and LA32S (standard) code, both subsets of it, but it
also decodes a few instructions that only LoongArch64 has, where real
LoongArch32 hardware would raise an exception. ``pcaddu18i`` and
``ldptr.w``/``stptr.w`` execute. The CRC instructions stop emulation with an
error on both emulators, because SmallWorld implements none of the p-code user
operations they lift to. The bounds-checked load/store instructions
(``ldgt``/``ldle``/``stgt``/``stle``) and ``asrtgt.d``/``asrtle.d`` lift to a
comparison that branches around such a user operation: Ghidra executes them
normally when the check passes and stops only when it fails, while angr raises
when it lifts any block containing one, whether or not the check would pass.

Some LA32R instructions also stop emulation, for the same reason:
``rdtimel.w``, ``rdtimeh.w``, ``rdcntid.w``, ``cpucfg`` and ``preld`` on both
emulators, and the ``dbar`` and ``ibar`` barriers on Ghidra only (angr treats
them as no-ops). Compilers emit ``dbar`` for atomics and fences, so such code
cannot run on Ghidra.

The language also gets some LA32R instructions wrong. Both emulators run its
p-code, so both compute the same wrong value without raising an error:

- ``rotr.w`` and ``rotri.w`` shift arithmetically, so rotating a value with
  bit 31 set fills the top with ones: ``0x80000000`` rotated right by 1 gives
  ``0xc0000000`` instead of ``0x40000000``. Rotating a value with bit 31 clear
  is correct.
- ``bstrins.w`` inserts the wrong bits at the wrong position: with ``a0 = -1``
  and ``t2 = 2``, ``bstrins.w a0, t2, 11, 4`` gives ``0xffffff00`` instead of
  ``0xfffff02f``.
- ``bytepick.w`` takes its bytes from the wrong ends of its operands:
  ``bytepick.w`` with ``rj = 0xedcba987``, ``rk = 0xfffffff9`` and ``sa = 1``
  gives ``0xffcba987`` instead of ``0xfffff9ed``. LLVM emits it for funnel
  shifts such as ``(a << 8) | (b >> 24)``.

These are bugs in Ghidra's LoongArch sleigh; LoongArch64's ``rotr.w``,
``bstrins.w`` and ``bytepick.w`` lift the same way.

angr's p-code engine has two bugs of its own that affect LoongArch32, as they
do its other p-code ISAs; Ghidra computes both correctly. It reads a register
operand that starts partway into a register from the register's start, so
``revb.2h`` gives ``0x44444444`` for ``0x11223344`` instead of ``0x22114433``.
It computes signed remainders as unsigned, so ``mod.w`` of -7 by 2 gives 1
instead of -1.

The test suite assembles LoongArch32 with zig. zig has no LoongArch32 libc, and
its LLVM has no 32-bit LoongArch CPU model to compile C for, so the tests are
assembly only; exitpoint and unmapped have hand-written stand-ins. There are no
System V ABI models for LoongArch32 yet.

**m68k angr:** angr runs Ghidra's ``68000:BE:32:default`` language, with these
gaps:

- ``cas`` and ``cas2`` branch within their own p-code, which angr's p-code
  engine can't run, so angr refuses a block containing them.
- ``trap``, ``trapv``, ``chk``, ``bkpt`` and the BCD instructions (``abcd``,
  ``sbcd``, ``nbcd``) raise, so syscall hooks never fire.
- The FPU doesn't run: its registers are in the 68881's 80-bit format, which
  angr's floating-point operations don't support (see the float support notes
  below).
- ``sfc``, ``dfc`` and ``tc`` read back at their real widths, but the language
  holds them in 4 bytes, so a ``movec`` that reads one into a register gives a
  partly symbolic value.

**mips32-micromips:** MIPS32 with microMIPS, which re-encodes MIPS32
Release 3/5 in 16- and 32-bit instructions over the same registers. Hardware
switches between microMIPS and standard MIPS32 on the low bit of a jump target
(``jalx`` switches outright). The current choice is the ``isa_mode``
pseudo-register: 1 for microMIPS, 0 for standard MIPS32. No architectural
register holds it, so SmallWorld adds one. Runs start in microMIPS.

Writing an odd pc selects microMIPS and stores the even address; writing an
even pc leaves ``isa_mode`` alone, so code that starts in standard MIPS32 needs
``isa_mode`` set to 0. The pc always reads back even.

- **Ghidra** switches between the two encodings as hardware does, on the
  ``MIPS:BE:32:micro`` and ``MIPS:LE:32:micro`` languages. ``isa_mode`` is
  their ``ISA_MODE`` context field.

  Ghidra's disassembler remembers the encoding it first decoded each address
  in, so code that one emulator has run in one encoding keeps decoding that
  way. Writing ``isa_mode``, or an odd pc, does not change it, though
  ``isa_mode`` reads back the new value; neither does a jump into that code in
  the other encoding. Run it in the other encoding on a fresh emulator. Ghidra
  offers no public way to clear that memory.
- **angr** runs microMIPS only, on the same languages through its p-code
  engine rather than VEX, which has no microMIPS decoder. angr's lifter has no
  way to set a context field, so SmallWorld gives the lifter angr caches for
  these languages a context that decodes microMIPS. A ``jalx``, or a ``jr`` to
  an even address, still decodes as microMIPS: following a switch would need
  angr's engine to act on sleigh's ``ISAModeSwitch``. An odd pc is stored even,
  as on the other backends, but ``isa_mode`` and the FPU registers are not
  available on angr. ``syscall`` reaches ``hook_syscall`` and
  ``hook_syscalls``, with the o32 convention (the number in ``v0``), because the
  machine definition rewrites it into a syscall exit as the SuperH ones do for
  ``trapa`` (see below).
- **Unicorn** starts every run in microMIPS, on the M14Kc CPU model, which runs
  microMIPS while the low bit of the pc is set. SmallWorld sets that bit
  whenever it starts a run or writes the pc. Unicorn does follow a jump into
  standard MIPS32, but it does not report its ISA mode, so ``isa_mode`` is not
  available and SmallWorld returns to microMIPS whenever a run resumes.

  Unicorn runs a microMIPS compact branch (one with no delay slot, such as
  ``jrc``, ``jraddiusp``, ``beqzc`` or ``bnezc``) even when a hook stops
  emulation on it, in both the pip and the nix builds. An exit point placed on
  such a branch is therefore run past, and single-stepping runs it too: the
  step that reaches the branch also takes it, ending at its target rather than
  at the branch, so a step-by-step trace on Unicorn leaves the branch out. This
  is a Unicorn bug that SmallWorld does not work around.

  Stock Unicorn 2.1.4, as pip installs it, mishandles a load or store in the
  delay slot of a branch that is not taken while a memory hook is installed,
  which SmallWorld always does: the next instruction, if it is a branch, raises
  a reserved-instruction exception. The Unicorn that SmallWorld's nix
  environment builds, from the ``mmio_map_pc_sync`` branch of
  ``appleflyerv3/unicorn``, does not have this bug.
- **PANDA** is not supported.

An ELF image flagged ``EF_MIPS_MICROMIPS`` loads as this platform, with a
warning if the entrypoint is standard MIPS32 code. Code addresses keep the ISA
bit, as on hardware: the entrypoint, the values of microMIPS code symbols
(set from ``STO_MICROMIPS`` in ``st_other``, so ``.symtab`` and ``.dynsym``
agree), and pointers relocated to them are odd. Writing one to the pc selects
microMIPS, and a function model placed at one hooks the even address. The flag
says only that the image contains some microMIPS code, so SmallWorld also warns
when function symbols show standard MIPS32 functions, which only Ghidra runs; a
stripped image cannot be checked.

Calls from microMIPS code set the low bit of ``ra``, and calls from standard
MIPS32 code leave it clear. Function models keep that bit: a model returns as
``jr ra`` would, to microMIPS for an odd ``ra`` and to standard MIPS32 for an
even one, where the backend can switch.

microMIPS code calls with MIPS32's o32 convention, so the System V C and POSIX
models exist for this platform as they do for MIPS32. Those that pass or
return floating-point values need the FPU registers, which angr and Unicorn do
not provide here.

**mips64 Panda:** The panda emulator currently runs code directly from physical memory.
In mips64, the upper half of the address space is reserved for MMIO devices.
Attempting to load state into this region will raise an exception.

**powerpc32-vle:** 32-bit PowerPC e200 running the Variable Length Encoding,
as on the VLE-capable e200 cores in NXP's MPC55xx/56xx/57xx (not the MPC5553
and MPC5554). VLE re-encodes the PowerPC instruction set in 16- and 32-bit
instructions with ``e_`` and ``se_`` mnemonics, over the same general-purpose
registers as ``powerpc32``. The e200 has no classic FPU, so the platform has no
``f0``-``f31`` or ``fpscr``.

- **angr** runs it on pypcode's own ``PowerPC:BE:32:e200`` language, which
  pypcode builds on Ghidra's VLE sleigh, rather than on VEX, which has no VLE
  decoder.

  - ``se_sc`` and ``e_sc`` reach syscall hooks. They follow the Linux PPC32
    syscall ABI: the number is in ``r0``, up to six arguments are in ``r3`` to
    ``r8``, and the result is in ``r3``. (``powerpc32`` on angr takes
    arguments in ``r3`` to ``r10``.)
  - The memory barriers and cache hints (``msync``, ``mbar``, ``se_isync``,
    ``tlbsync``, ``dcbf``, ``dcbst``, ``dcbi``, ``dcbt``, ``dcbtst``, ``icbi``
    and ``icbt``) do nothing. The other privileged and atomic instructions
    raise an error, including ``dcbz``, ``dcba``, ``stwcx.``, ``wrtee``,
    ``wrteei``, ``tlbwe``, ``tw`` and the interrupt returns (``se_rfi`` and the
    like).
  - The language miscomputes the wrap-around mask of ``e_rlwinm`` and
    ``e_rlwimi`` when MB > ME: it clears bits MB and ME, which the mask should
    keep. For example, ``e_rlwinm r14,r4,15,17,7`` masks with ``0xfe003fff``
    instead of ``0xff007fff``. Compilers emit such masks for ``x & 0xff00ffff``
    and the like. This is an upstream sleigh bug.
  - The SPE floating-point instructions (``efs*``) do not all run.
    ``efscfsi`` and ``efsctsiz`` branch inside their own p-code, which angr's
    p-code engine cannot run, so angr refuses a block containing them, or any
    other instruction that does so, with ``EmulationExecFailure``.
    ``efsmul``, ``efsdiv`` and ``efssub`` run, checked on single values; the
    other ``efs*`` instructions are untested on angr.
  - There are no C library models, calling contexts, ``FunctionPointer`` or
    ``ReturnConstant`` for ``powerpc32-vle``; looking one up raises
    ``ValueError``.

- **Ghidra:** upstream Ghidra, including 12.1.2, the version SmallWorld's nix
  environment provides, has no 32-bit e200 language. Its only VLE languages are
  the 64-bit Power ISA 3.0 ones, whose registers and arithmetic are 64-bit.
- **Unicorn and PANDA** (QEMU) have no VLE decoder, and Capstone cannot
  disassemble VLE, so analyses that disassemble with Capstone do not work on it.

The ELF header doesn't distinguish VLE from standard PowerPC code, so the ELF
loader reads the VLE flags binutils sets: ``SHF_PPC_VLE`` on code sections and
``PF_PPC_VLE`` on segments, so an image without section headers is recognized
too. VLE's own code relocations (``R_PPC_VLE_*``) are not supported, so load a
linked executable rather than an object file.

The platform decodes VLE for the whole run. Several e200 cores can also run
standard PowerPC code in pages not marked VLE, but SmallWorld does not switch
encodings by region. The register-register instructions (primary opcode 31,
such as ``add``, ``cmpw``, ``lwzx`` and ``mfspr``) are encoded alike, but
branches, immediate-form arithmetic and D-form loads and stores are not
(``addi`` reads as ``e_lha``, ``b`` as ``se_li``), so standard code is
misdecoded. The loader loads a file that mixes both as ``powerpc32-vle`` and
logs a warning; pass ``platform`` to choose ``powerpc32`` instead.

The test suite assembles VLE with GNU binutils (``as -mvle``), since zig's LLVM
assembler has no VLE support.

**riscv64:** The RISCV64 ISA is made up of an incredibly small core feature set,
and a large number of extensions.  I can't get the assembler to build
for some of the extensions, so I haven't tested anywhere near all of them.
Also, the standards for this ISA are still being developed,
so some things like the syscall convention are something of a guess.

**SuperH:** SmallWorld models two SuperH generations, and they are not the same ISA.

*sh1* and *sh2* are SH-1 and SH-2, big-endian. Each runs on Ghidra's own
language for it (``SuperH:BE:32:SH-1`` and ``SH-2``), built from the same
specification as SH-2A, so an instruction from a later version is refused as on
the real CPU rather than run: SH-1 has none of the nine instructions SH-2
added (``mul.l``, ``dmuls.l``, ``dmulu.l``, ``mac.l``, ``dt``, ``braf``,
``bsrf``, ``bt/s`` and ``bf/s``), and SH-2 has none of SH-2A's instructions. Neither has an
FPU or SH-2A's ``tbr``. They run on angr and Ghidra only: Styx and Panda's
patched QEMU model only SH-2A and SH-4. The ELF loader recognizes them from
``e_flags``. SH-2E (SH-2 with a single-precision FPU) has no Ghidra language,
so an SH-2E image still loads as SH-2A-FPU, its superset.

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
  SuperH, so every SuperH platform is ``No Support`` rather than merely untested.
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

  The **SH-4 rows of the table above assume a patched Styx.** Upstream Styx
  1.2.0 has the SH-4 machinery on its Rust side but never exposes it to Python;
  ``nix/patches/styx-superh4-target.patch`` adds the ``Target.SuperH4Be`` /
  ``Target.SuperH4Le`` enum entries, so a plain
  ``pip install smallworld-re[emu-styx]`` gets SH-2A but not SH-4 and raises
  ``ConfigurationError`` for the latter. ``smallworld.emulators.styx.machdefs
  .superh4.STYX_SUPPORTS_SUPERH4`` reports which build is installed. Styx is
  also absent from every SH-4 scenario except ``testfloat`` for this reason, so
  its SH-4 coverage is much thinner than the table suggests.

**⚠** ``bclr #imm3,Rn`` **corrupts memory on angr and Styx.** The two bundled copies
of Ghidra's SH-2A specification are not identical, and this is their only
difference. Ghidra 12.1.2 implements the register form correctly as
``rn = rn & ~(1 << imm)``; the copies shipped in pypcode 3.3.3 and Styx instead
carry ``local b = *:1(rn); *:1(rn) = b & ~(1 << imm)`` - the semantics of the
*memory* form ``bclr.b #imm3,@(disp,Rn)`` applied to the register form. So the
register is left unmodified and a byte of memory at the address held in ``Rn`` is
rewritten instead. Because that spurious access generally succeeds (angr's memory
is lazily symbolic; Styx maps a flat 4 GiB), it corrupts memory silently rather
than faulting. Only the Ghidra backend gets this instruction right.

**⚠** ``mac.w`` **and** ``mac.l`` **are wrong under angr and Ghidra on sh1, sh2
and sh2a-fpu.** Ghidra's ``superh.sinc``, which all three are built from, lifts
both with p-code branches within the instruction, which angr's p-code engine
cannot run: angr stops with a raw ``AssertionError`` ("FIXME: Test
statement_offset behavior") rather than an ``EmulationError``. Ghidra runs them
but gets the result wrong. ``mac.w`` reads each operand as four bytes and
multiplies their second halfwords, and sets MACH to ``0xffffffff`` for a
positive product; ``mac.l`` sets MACH wrongly (``0x1000f`` rather than ``0xf``
for ``0x30005 * 0x50007``). This was measured with ``@r1+,@r2+`` operands and S
clear; Panda and Styx were not measured.

**⚠ SH-4** ``bsr`` **does not set PR under angr or Ghidra.** This is a defect in
Ghidra's SuperH4 sleigh specification, not in SmallWorld, and it affects both
backends that derive from it. In ``SuperH4.sinc``, ``:bsr`` - the ordinary
PC-relative call - performs its ``delayslot(1); call ...`` with no assignment to
``PR`` at all, so the return address is simply never recorded. Ghidra's separate
SH-2A specification gets it right, so *sh2a-fpu is unaffected*, and Panda runs
on real QEMU and is also unaffected. On SH-4 under angr, ``pr`` is left
unconstrained and reading it raises ``SymbolicValueError``; under Ghidra it
reads back as zero and the return faults with
``EmulationFetchUnmappedFailure``.

The defect is limited to ``:bsr``. ``:bsrf`` and ``:jsr`` both assign
``PR = inst_next``, and sleigh's ``inst_next`` counts the delay slot as part of
the instruction, so that is exactly the architectural ``inst_start + 4``. This
was confirmed by measurement rather than by reading the specification: a ``jsr``
whose delay slot increments a register - so that returning into the slot would
increment it twice - yields ``pr = inst_start + 4`` and a single increment on
all of angr, Ghidra and Panda, for sh2a, sh4 and sh4el alike. **No two-byte
correction is needed, and none should be applied.**

So on SH-4 under angr and Ghidra, use ``jsr @Rn`` (or ``bsrf``) rather than
``bsr`` if you need calls; materialise the target with
``mov #imm,Rn``/``shll8`` rather than a PC-relative literal pool. The ``hooking``
scenario does exactly this and passes on all three SH-4 engines. The scenarios
that deliberately keep ``bsr``, to hold the defect pinned until it is fixed
upstream, are ``call``, ``strlen`` and ``static_buf``; those skip ``sh4`` and
``sh4el`` on angr and Ghidra.

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

**SuperH event handlers:** instruction, function and memory-access hooks work on
every SuperH platform under angr and Ghidra, and on sh2a-fpu, sh4 and sh4el under
Panda. Syscall hooks work under
angr, which is the only backend that implements ``hook_syscall``/``hook_syscalls``
at all, so that is not a SuperH limitation. Interrupt hooks work under Panda;
Unicorn and Styx also implement ``hook_interrupt``/``hook_interrupts``, but
Unicorn has no SuperH support and SuperH's ``trapa`` never reaches Styx's
interrupt machinery. Four SuperH specifics are worth knowing before writing a
hook:

- **Styx hangs once a hook fires.** Installing an instruction or memory hook and
  reaching it hangs the run rather than raising, on sh2a and on both SH-4
  endiannesses. A hook that is installed but never reached is harmless, and Styx
  is otherwise correct on these platforms - it runs the delay-slot scenario to
  the right answer in both byte orders - so this is a hook-machinery problem
  rather than a core problem. Every SuperH scenario that installs a hook skips
  its styx variant for this reason.
- **Delay slots change which PC a hook reports**, and the three backends do it
  three different ways. For a branch at *A* whose delay slot at *A+2* writes
  memory: Ghidra folds the pair and attributes the write to *A*, firing no
  instruction hook for *A+2* at all; angr also folds, but *does* fire the hook,
  reporting *A* as the PC; Panda translates the two separately and reports
  *A+2*, which is the architecturally faithful answer. So a harness that hooks a
  delay slot by address gets three different observations. ``tests/delay`` pins
  all three.
- ``trapa`` **is an interrupt on Panda and nothing at all on the sleigh
  backends.** Panda raises it through ``hook_interrupts`` as interrupt 352
  (``0x160``), because QEMU's ``helper_trapa()`` sets ``exception_index`` to that
  value. Sleigh instead models ``trapa`` as machine state rather than as an
  event - ``SuperH4.sinc`` lowers it to the ``TrapAlways`` userop and
  ``superh.sinc`` lowers it to a literal vector dispatch through
  ``VBR + imm*4`` - so Ghidra and angr cannot deliver it as an interrupt.
  Two caveats: the 352 is an artifact of QEMU delivering SH-2A ``trapa`` the SH-4
  way, whereas real SH-2A dispatches through the table at address 0, so a
  harness that installs a real handler will see the wrong vector on SH-2A; and
  Styx gets this wrong outright, performing ``trapa``'s stack writes and then
  falling through to the next instruction instead of vectoring, raising nothing.
- ``trapa`` **is a syscall on angr, and that takes explicit machdef work.**
  angr's Pcode lifter derives the jumpkind from the terminating p-code opcode
  alone, and sleigh p-code has no syscall opcode - so *no* Pcode-lifted
  architecture gets ``Ijk_Sys_syscall`` from the lifter, and syscall hooks are
  unreachable without help. The SuperH machine definitions therefore rewrite the
  lifted block themselves, exactly as the Xtensa one does: they locate the trap,
  truncate the block at that instruction, set the jumpkind by hand, and register
  a Linux/SH syscall convention (number in ``r3``, arguments
  ``r4``-``r7``/``r0``/``r1``, result in ``r0``, resume two bytes past the trap -
  taken from QEMU's ``linux-user/sh4/cpu_loop.c``). Two consequences: the trap
  immediate is deliberately *not* checked, so **any** ``trapa`` reads as a
  syscall, matching QEMU, which keys on the exception number alone; and a
  ``trapa`` sitting in a branch's delay slot is declined rather than rewritten,
  because sleigh lifts a branch and its delay slot under a single IMARK, leaving
  no boundary to truncate at without discarding the branch. Delay-slot ``trapa``
  is architecturally prohibited on SuperH anyway, but assemblers accept it.

**V850:** *v850* is Renesas V850E1, V850E2 and V850E2M, little-endian, on angr
and Ghidra. Both use Ghidra's ``V850:LE:32:default`` language, which pip's
pypcode also ships, so angr's V850 support works in a pip install. Unicorn,
QEMU (and so Panda) and Styx have no V850 model.

That language covers the three cores in one, including V850E2M's FPU, with no
way to select a core: it accepts V850E2 and V850E2M instructions in V850E1 code.
GNU binutils calls V850E2M's instruction set V850E2V3 (``-mv850e2v3``).

It does not model RH850 (V850E3v5), and SmallWorld has no RH850 platform. Most
RH850-only instructions fail to decode, but some reuse encodings that V850
decodes as other instructions, and run as those without any error:

- ``loop`` runs as ``mulhi``, and ``synci`` as ``mov``, both writing ``r0``.
- ``ld.dw`` and ``st.dw`` are six bytes long. Their first four run as an
  ``ld.bu`` into ``r0``, with the second halfword as its displacement, and the
  last halfword then runs as an instruction of its own: a ``nop`` when it is
  zero, otherwise whatever it decodes as, which may swallow the following
  instruction's first halfword and leave decoding out of step.
- The 17-bit-displacement forms of ``br`` and the conditional branches run as
  ``ld.hu`` into ``r0``, so the branch is never taken.
- ``dbhvtrap`` runs as ``divh r0, r28``, and ``dbcp`` as ``divh r0, r29``,
  which zeroes ``r29`` on Ghidra and raises an error on angr.

The ELF loader refuses ``EM_V800`` images, built for Renesas's RH850 ABI, which
is GNU as's default for V850 code as well as RH850. Its relocations are numbered differently from the
GCC ABI's, and it does not record which core the code is for. Build V850 code
for the GCC ABI (``-mgcc-abi``) instead. ``EM_V850`` images, built for the GCC
ABI, record their core, and load without a warning unless it is V850E3v5.

Relocatable objects load with their absolute (``ABS32``), ``hi()``/``lo()``
(``HI16_S``, ``HI16``, ``LO16``, ``LO16_S1``) and branch (``9_PCREL``,
``22_PCREL``) relocations applied. Other relocation types, including the
small-data ones relative to ``gp``, ``ep`` or ``r0``, stop the load with an
error.

Some V850 instructions do not run, or run wrongly:

- ``di``, ``ei``, ``halt``, ``synce``, ``syncm``, ``syncp`` and the saturating
  arithmetic instructions (``satadd``, ``satsub``, ``satsubi``, ``satsubr``)
  lift to p-code user operations. angr's machine definition implements them:
  ``di`` and ``ei`` only set and clear ``PSW.ID``, the sync instructions do
  nothing, ``halt`` stops emulation after it, and the saturating instructions
  clamp an overflowing result. On Ghidra they stop emulation with
  an error, after the instruction's earlier p-code has run: ``satadd`` has
  already written the unsaturated sum and the flags, and ``di`` has set
  ``PSW.ID``.
- ``rmtrap`` runs as ``divh r0, ep``, without any error on Ghidra, where it
  zeroes ``ep``; angr raises an error.
- The language computes ``bsw``, ``bsh`` and ``hsw`` wrong, without any error:
  it shifts each byte or halfword before widening it, so the shifted bits are
  lost. For ``0x11223344``, Ghidra gives ``0x11``, ``0x33`` and ``0x1122``
  instead of ``0x44332211``, ``0x22114433`` and ``0x33441122``, and angr gives a
  different wrong result (``0x44``, ``0x44`` and ``0x3344``) because of the
  sub-register bug below.
- The language computes the two-operand ``divh reg1, reg2`` as an unsigned
  division by all 32 bits of ``reg1``, not a signed division by its low
  halfword, on both emulators: -7 divided by -3 gives 0, with Z set, instead of
  2. The three-operand ``divh`` is correct.
- On angr, ``sch0l``, ``sch0r``, ``sch1l`` and ``sch1r`` raise an
  ``AssertionError``, and ``reti`` returning from an exception (``PSW.EP`` set)
  leaves ``pc`` and ``PSW`` unchanged when run, and stops with "Path diverged"
  when stepped. Their p-code branches within the instruction, which angr's
  p-code engine does not handle. Ghidra runs them correctly.
- angr's p-code engine computes signed division and remainder as unsigned, so
  ``div``, the three-operand ``divh`` and ``divq`` give wrong results on angr
  when an operand is negative: ``div`` of -7 by 3 gives ``0x55555553``,
  remainder 0, instead of -2, remainder -1. It also reads a register operand
  that starts partway into a register from the register's start. Both affect
  angr's other p-code ISAs too; Ghidra gets both right.
- ``trap`` stops ``GhidraSymbolicEmulator`` with a Z3 sort-mismatch error, after
  ``EIPC``, ``EIPSW`` and ``EIIC`` have been written, and before ``pc``
  changes. Ghidra's symbolic extension, SymZ3, returns the whole of a p-code
  temporary when ``trap`` reads only its low halfword. ``GhidraEmulator`` and
  angr run ``trap`` correctly.

V850E2M's FPU runs on Ghidra and angr; the ``floats`` scenario checks
single-precision ``addf.s`` on both. The language gets some conversions wrong,
without any error, and both emulators compute the same wrong values:

- The ``cvtf`` conversions from floating point to integer truncate instead of
  rounding as ``FPSR`` selects: ``cvtf.sw`` of 2.7 gives 2, not 3, under the
  default round-to-nearest. ``trncf``, ``ceilf`` and ``floorf`` are correct.
- The conversions from unsigned integers to floating point treat their operand
  as signed: ``cvtf.uws`` of ``0xc0000000`` gives -1073741824.0, not
  3221225472.0.

The ``roundf`` instructions, which GNU as accepts only with ``-mextension``, do
not decode.

**x86-16:** ``Architecture.X86_16`` is x86 real mode, as the 80386 runs it:
16-bit code that may still use the 32-bit registers through the operand-size
prefix. ``pc`` is the linear address of the next instruction, ``cs * 16 + ip``,
and is a register of its own rather than an alias of ``eip``. Set the segment
registers and ``pc``; the CPU's segment registers start at 0. Use
``X86RealModeStack.get_segment()`` and ``get_offset()`` to load ``ss`` and
``sp``.

- **Unicorn** derives ``ip`` from ``pc`` and ``cs``, and ``eip`` holds the
  offset into the code segment. It models segmentation, apart from far
  returns (below).
- **angr and Ghidra** both run Ghidra's ``x86:LE:16:Real Mode`` language.
  ``eip`` is not available on them (set ``pc`` and ``cs`` instead), and ``ip``
  is the low half of the linear pc, so it is the offset into cs only when cs
  is a multiple of 0x1000.
- Function models and hooks assume near calls: they pop a 2-byte offset from
  ``ss:sp`` and return to it in the current ``cs``. A function reached by a
  far call needs a model that sets ``skip_return`` and returns itself.
- Models' pointer arguments are linear addresses, so they only match what
  the code means when the segment the code reads them through is 0.
- The Ghidra symbolic emulator, PANDA and Triton do not support real mode.
- SmallWorld's analyses decode real-mode instructions with Capstone, since
  the p-code analysis can't see through the language's ``segment`` op.

**⚠ angr and Ghidra need code segments on a 64 KiB boundary.** Ghidra's
real-mode language infers the code segment from the linear pc as
``(pc >> 4) & 0xf000``, so code must run from a segment that starts on a
64 KiB boundary: a cs that is a multiple of 0x1000, such as ``0000:7c00`` or
``1000:0000``. In any other segment, near calls push the wrong return offset,
and indirect near jumps and calls, and ``cs:`` overrides, overwrite cs with
the inferred value. angr refuses to run such a segment. Ghidra runs it, and
computes a wrong result: it only faults when a wrong address happens to be
unmapped.

**⚠ More of the real-mode language ignores segments on angr and Ghidra.**
These are defects in Ghidra's language, so they are wrong in any code
segment, and are right only when the segment they ignore is 0:

- ``iret``, ``retf imm16`` and ``jmp far [m16:16]`` jump to the offset they
  pop or load as a linear address, without its segment; ``call far [m16:16]``
  jumps correctly, but leaves ``cs`` unchanged.
- Accesses with the address-size prefix (``0x67``), including 32-bit stack
  accesses, ignore their segment's base.
- ``xlat`` reads from ``bx + al`` without ``ds`` or a segment override.

**⚠ Unicorn gets far returns wrong.** Unicorn 2.1.4 in 16-bit mode loads the
new ``cs`` on ``retf``, but keeps the old ``ip``, whenever a memory-read hook
is installed, and SmallWorld always installs one. Far calls, far jumps,
``iret`` and ``int`` are correct.

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
- **angr's p-code engine leaves floating point unimplemented upstream**: every
  ``OpBehaviorFloat*`` in ``angr/engines/pcode/behavior.py`` raises
  ``AngrError("Not implemented!")``. SmallWorld supplies its own, in
  ``smallworld/emulators/angr/machdefs/pcode_float.py``, and runs every
  Pcode-backed architecture with them, though only SH-2A single precision and
  V850E2M's ``addf.s`` are measured; TriCore and LoongArch64 are untested.
  Xtensa stays at No: Ghidra's sleigh includes its optional FPU, but
  SmallWorld's angr machdef for it exposes no floating-point registers. m68k stays at No too: its language
  holds the FPU registers in the 68881's 80-bit format, which these behaviors
  don't support, so even ``fmove.s`` into an FPU register raises. The behaviors
  follow IEEE 754, rounding to
  nearest, ties to even. A comparison with a NaN is unordered, so
  ``FLOAT_NOTEQUAL`` is true and the others false, and ``-0`` equals ``+0``;
  Ghidra's p-code reference says ``FLOAT_NOTEQUAL`` is false on a NaN. Where
  IEEE 754 leaves a result open, a NaN result is the canonical quiet NaN, and
  ``FLOAT_TRUNC`` saturates to the output's signed range, with NaN giving 0.
  ``FLOAT_ROUND``, which has no IEEE 754 counterpart, rounds halfway cases up,
  as Ghidra does.

  They are checked against the arithmetic Ghidra's p-code emulator runs. That
  departs from IEEE 754, and so from angr, in these places:

  - **Subnormal underflow.** Half- and single-precision ``FLOAT_MULT``,
    ``FLOAT_DIV`` and narrowing ``FLOAT_FLOAT2FLOAT`` give zero for a result
    between half the least subnormal and the least subnormal, which rounds to
    the least subnormal: ``0x00000001`` times ``0x3F000001`` gives
    ``0x00000000``, and ``2**-150 * (1 + 2**-20)`` narrowed to single
    precision gives ``0x00000000``. Double precision is unaffected.
  - **Double rounding.** ``FLOAT_INT2FLOAT`` converts through a double, so an
    integer wider than 53 bits can round twice on its way to single or half
    precision: ``2**60 + 2**36 + 1`` gives ``0x5D800000``, not ``0x5D800001``.
  - **FLOAT_ROUND** computes ``floor(x + 0.5)`` in floating point, so
    ``0.49999999999999994`` rounds to 1.
  - **NaNs.** ``FLOAT_NEG`` and ``FLOAT_ABS`` of a NaN give a default NaN,
    losing its payload; IEEE 754 changes only the sign bit. Ghidra's NaN
    results are also the host's, so on x86-64 one produced by an invalid
    operation has its sign set (``0xFFC00000``). IEEE 754 allows that, but
    the bits differ from angr's.
  - **Out-of-range FLOAT_TRUNC.** IEEE 754 leaves the result open. Ghidra
    saturates to a 64-bit integer and keeps its low bits, so ``+inf`` to 4
    bytes gives ``0xFFFFFFFF`` and ``-inf`` gives 0, where angr gives
    ``0x7FFFFFFF`` and ``0x80000000``.

  Ghidra evaluates operands wider than 8 bytes through a separate BigInteger
  implementation, with other differences; angr supports no such format.

  Concrete operands support half, single and double precision. Symbolic ones
  are solved by Z3, and support single and double precision only, because
  claripy has no other formats; symbolic floating-point queries can take
  seconds. Neither supports the 80-bit formats of x87 and the 68881.

  angr's p-code engine also cannot branch between the p-code ops of a single
  instruction, which rules out instructions whose semantics contain an
  if/else. SH-4's floating-point instructions are such an if/else on
  ``FPSCR_PR``, so SH-4 floating point still does not run on angr; SH-2A's does.
  A harness that writes ``fpscr`` directly meets a second problem first:
  ``FPSCR_PR`` is then not stale, as under Ghidra (see below), but
  unconstrained, so each floating-point instruction forks into both paths.
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
``Linux-x86_64-GCC``; ``testfloatFor`` in ``nix/runtime-support.nix`` puts
``testfloat_gen`` and ``testfloat_ver`` on the *developer shell's* ``PATH`` on
little-endian 64-bit Linux. It is deliberately kept out of ``runtimeToolsFor``,
so ``nix build`` and the Docker image do not carry a test-only conformance
suite - which also means ``testfloat_gen`` is absent from a plain runtime
environment, and the scenario must be run from ``nix develop``. The reference is
built with ``SPECIALIZE_TYPE=8086-SSE``.

Each architecture supplies one assembly file containing four loop kernels - one
per (precision, arity) - at fixed offsets, sharing one exit label. The harness
picks an entry point, patches the single arithmetic instruction in place, and
lets the guest walk an array. The contract has the same *shape* everywhere - an
input cursor, an output cursor and a case count - but each architecture names its
own registers in ``tests/harness/scenarios/testfloat_arch/``: ``r4``/``r5``/``r6``
on SuperH, ``r0``/``r1``/``r2`` on armhf, ``x0``/``x1``/``x2`` on aarch64,
``esi``/``edi``/``ecx`` on i386 and ``rdi``/``rsi``/``rdx`` on amd64. On SuperH
``r7`` additionally carries the FPSCR value that the kernel installs with
``lds`` - a direct register write would leave the split ``FPSCR_PR`` stale, as
described above. A
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

Measured results, at 2000 generated cases per function (``run_case.py testfloat
<variant> --cases 2000``; the harness default, ``testfloat.DEFAULT_CASES``, is
3000, so an unqualified run exercises more cases than the table was measured
against). The five functions per precision are add, subtract, multiply, divide
and square root.

.. csv-table:: TestFloat results
    :file: testfloat_results.csv
    :header-rows: 1
    :stub-columns: 1

Little-endian SuperH (``sh4el``) matches big-endian ``sh4`` in every cell.

Every skip is an upstream defect, reduced to a minimal case first:

- **angr** is skipped on SH-4, whose floating-point instructions branch within
  the instruction, which angr's p-code engine cannot do (see above). The
  ``floats`` scenario, which writes ``fpscr`` directly, fails earlier, because
  angr leaves ``FPSCR_PR`` unconstrained. On SH-2A,
  angr passes all five single-precision functions, including the multiply and
  divide cases where Ghidra flushes subnormal results to zero.
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
  unaffected. It reproduces on **three** unrelated instruction sets, which is
  what settles the attribution: SuperH ``fmul``, armhf ``vmul.f32`` and amd64
  ``mulss`` all return signed zero for the same operands, so ``amd64`` and
  ``armhf`` carry the same two per-function skips as SuperH.
- **armhf square root** is skipped under ``angr``. ARM's ``vsqrt.f32`` and
  ``vsqrt.f64`` lower to VEX's *scalar* ``Iop_SqrtF32``/``Iop_SqrtF64``, and
  angr implements neither, so the run raises
  ``UnsupportedIROpError``. This is specific to the scalar opcodes rather than
  to square root: amd64's ``sqrtss``/``sqrtsd`` lower to the SIMD
  ``Iop_Sqrt32F0x4``/``Iop_Sqrt64F0x2``, which angr does implement, so
  ``amd64.angr`` and ``aarch64.angr`` pass all five functions.
- **Panda is skipped on every non-SuperH architecture here**, always because its
  bare ``-M configurable`` machine brings the CPU up with the floating-point
  unit switched off and nothing in the harness able to switch it on. On x86-64
  the CPU starts in real mode with ``CR4=0`` and every ``xmm`` instruction is
  ``#UD``; on i386 likewise; on ARM every VFP instruction raises ``EXCP_UDEF``
  (reported as ``Panda exception 1``), which a bare ``vmov.f32 s0,s1`` blob
  reproduces on its own, and the ``FPEXC.EN`` write the kernels already perform
  for Unicorn's benefit is not sufficient - ARMv7-A also gates VFP behind
  ``CPACR``'s ``cp10``/``cp11`` fields, a privileged CP15 register. SuperH is
  the exception because its FPU needs no enable step, which is why Panda is the
  only backend passing all ten SuperH functions.

Panda passes all ten functions on sh2a-fpu, sh4 and sh4el, which is the
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

