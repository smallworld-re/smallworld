# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `AngrEmulator` reads and writes part of a register correctly on p-code
  architectures. angr's p-code engine looked a register varnode up by the
  name of the register containing it, losing its offset within it, so an
  instruction using a big-endian register's low half (SuperH `mulu.w`) used
  the high half instead. This also fixes SuperH `mov.w Rm,@Rn` and
  `mov.b Rm,@Rn`, which stored `Rm`'s high bytes, so a halfword store of
  `0x1234` wrote zero.
- `GhidraEmulator` and `GhidraSymbolicEmulator` report an instruction their
  language cannot decode as `EmulationExecInvalidFailure`, as the other
  backends do, rather than letting Ghidra's `DecodePcodeExecutionException`
  escape, or its `InstructionDecodeException` for an undecodable delay-slot
  instruction.
- The ELF loader reports a machine type LIEF does not know as an unknown
  `e_machine` value, rather than failing with an `AttributeError`, and loads
  such an image when given a platform with `ignore_platform`.
- `Memory` state objects with large values are now stringified much faster.
- `InputColorizerAnalysis` can now handle 32-bit cpu.
- `TritonEmulator` no longer returns from a hooked function twice; the hook
  itself performs the return, as it does on every other backend.
- `TritonEmulator` reports unmapped fetches, reads and writes instead of
  silently succeeding on Triton's flat, lazy memory.
- `TritonEmulator` no longer raises a spurious memory-read hook for the
  destination of an ARM32 store.
- `TritonEmulator` treats `hlt` (and the AArch64/RISC-V wait-for-event
  instructions) as a clean stop rather than an invalid instruction.
- `TritonEmulator.run()` returns when execution reaches an exit point or leaves
  its bounds, instead of letting the stop escape to the caller.
- `TritonSymbolicEmulator` handles labels whose names are not SMT-LIB symbols
  (`"fake return address"`), and symbolic memory of any size rather than only
  Triton's power-of-two access widths.
- `TritonEmulator` runs x86 `rep`-prefixed string instructions to completion
  instead of stopping after the first iteration.
- `TritonEmulator` reports an undecodable instruction as
  `EmulationExecInvalidFailure` rather than letting Triton's own `TypeError`
  escape.
- `TritonEmulator` honors a PC written by an instruction, syscall or interrupt
  hook, dispatches both the global and the numbered interrupt hook, and no
  longer spins forever on a function hook that leaves PC alone.
- `TritonEmulator` recognises predicated ARM32 traps (`svcne`) and evaluates
  their condition instead of reporting them as invalid instructions, and
  rejects a memory-read hook that returns the wrong number of bytes.
- `TritonSymbolicEmulator` survives a branch on symbolic data, detects memory
  that execution made symbolic, records symbolic writes in the memory map,
  keeps its internal accesses out of the user's memory hooks, and binds a
  register label written through an alias (`edi` for `rdi`, `pc` for `rip`).
- Reusing one label for two values no longer makes the Triton-to-claripy
  bridge emit a duplicate SMT-LIB declaration.
- The Triton machine definitions no longer resolve `triton.ARCH` at import
  time, so a Triton build missing one architecture fails when that
  architecture is requested rather than breaking `import smallworld`, and the
  "install the [emu-triton] extra" error is reachable again.

### Added

- angr runs floating-point p-code. angr's p-code engine leaves every float
  operation unimplemented, so SmallWorld supplies its own. They follow IEEE
  754, and the docs list where Ghidra's emulator departs from it: concrete
  operands in half, single and double precision, symbolic
  ones in single and double precision through Z3. SH-2A floating point now runs
  on angr and passes TestFloat's single-precision functions. SH-4's does not
  yet, because its float instructions branch within the instruction, which
  angr's p-code engine cannot do.
- `Architecture.SUPERH_SH1` and `Architecture.SUPERH_SH2`, big-endian, on the
  angr and Ghidra backends, using Ghidra's SH-1 and SH-2 languages. Each
  refuses the later versions' instructions, as the CPU does, where SH-1 and
  SH-2 code used to run as SH-2A. The ELF loader recognizes them from
  `e_flags`.
- `Architecture.LOONGARCH32`, 32-bit LoongArch, on angr and Ghidra through
  Ghidra's `Loongarch:LE:32:ilp32d` language. It decodes LA32R and LA32S
  code, and also accepts some LoongArch64-only instructions. Some instructions
  stop emulation, and the language computes `rotr.w`, `rotri.w`, `bstrins.w`
  and `bytepick.w` wrong; the platform support docs list both. ELF32
  `EM_LOONGARCH` images now load as this platform instead of being refused,
  with `R_LARCH_32` relocations. There are no System V ABI models for it yet.
- `AngrEmulator` supports M68K (68040), using Ghidra's `68000:BE:32:default`
  p-code, with a stack-based System V calling convention for function hooks.
  On angr, the `sfc`, `dfc` and `tc` control registers keep their real widths
  even though sleigh widens them to 4 bytes. `cas`/`cas2` are refused, and
  traps, syscalls, the BCD instructions and the FPU aren't supported; see the
  platform support notes.
- `Architecture.V850`, Renesas V850E1, V850E2 and V850E2M, on the angr and
  Ghidra backends, using Ghidra's V850 language. The ELF loader loads GCC-ABI
  (`EM_V850`) images, applying the common relocation types in relocatable
  objects, and refuses RH850-ABI (`EM_V800`) ones. RH850's additional
  instructions are not modelled, and a few of them run as different V850
  instructions. Some V850 instructions stop emulation or compute wrong
  results; the platform support docs list them. Test binaries are built with
  GNU binutils for `v850-elf`, built from source in `ci/flake.nix` because
  nixpkgs has no V850 platform.
- `Architecture.POWERPC32_VLE`, PowerPC e200 with the Variable Length
  Encoding, on the angr backend through pypcode's own e200 p-code language.
  Upstream Ghidra has no 32-bit e200 language, and Unicorn, PANDA and Capstone
  have no VLE support. `se_sc` and `e_sc` reach angr's syscall hooks, and the
  memory barriers and cache hints run as no-ops. The ELF loader recognizes VLE
  executables by the section and segment flags binutils sets on VLE code. There
  are no C library models for VLE. The language miscomputes wrap-around
  `e_rlwinm`/`e_rlwimi` masks, and angr refuses the SPE instructions that
  branch inside their own p-code, such as `efscfsi` (see the platform support
  notes). The test suite assembles VLE with GNU binutils, since zig's
  assembler cannot.
- `Architecture.X86_16`, x86 real mode, on the Unicorn, angr and Ghidra
  backends. `pc` is the linear address `cs * 16 + ip`. angr and Ghidra use
  Ghidra's real-mode language, which only handles code segments that start on
  a 64 KiB boundary; Unicorn handles any segment. `X86RealModeStack` gives the
  `ss:sp` for its stack.
- `UnicornMachineDef.pc_from_engine()`/`pc_to_engine()`, for machines whose
  program counter register is not the linear pc.
- `GhidraMachineDef.evaluate_userop()`, for sleigh user ops that Ghidra's
  emulator does not provide, and `GhidraMachineDef.ram_address_size`, for
  machines whose RAM offsets are wider than their pointers.
- A `testfloat` scenario that checks emulated FPUs against
  [Berkeley TestFloat](http://www.jhauser.us/arithmetic/TestFloat.html).
  TestFloat and its SoftFloat reference are built from upstream by
  `nix/testfloat.nix` rather than vendored, and `testfloat_gen`/`testfloat_ver`
  are on `PATH` inside `nix develop`. Results are compared; exception flags and
  NaN payloads are not (the latter are architecture-specific by design).
- Renesas SuperH support: `Architecture.SUPERH_SH2A_FPU` (big-endian) and
  `Architecture.SUPERH_SH4` (both endiannesses), across the angr, Ghidra, Panda
  and Styx backends. Unicorn has no SuperH emulation of any kind, so it is
  unsupported. QEMU has no SH-2A model at all, so Panda's SH-2A support comes
  from a local patch adding the SH-2A ISA to QEMU's `target/sh4`; see
  `nix/patches/README.panda-qemu-sh2a.md` for what it does and does not
  implement.
- `TritonEmulator` and `TritonSymbolicEmulator` emulator backends based on the
  Triton dynamic binary analysis framework (`[emu-triton]` extra), covering
  x86, x86-64, ARM32, AArch64, and RISC-V 64, with concrete emulation, linear
  symbolic execution, and taint-analysis escape hatches.
- `TritonEmulator` implements `SyscallHookable`, dispatching syscall hooks for
  `syscall`/`svc`/`ecall`/`int 0x80` using each platform's Linux syscall-number
  register.
- `Filter` analyses that simply listen to the hint stream.
- `Instruction` classes that provide information on instruction semantics, with
  methods for capturing concrete values.
- `Value.type` for storing optional type information.
- `Value.label` for storing optional label information.
- `Emulator.hook()` for dynamic hooking.
- `Emulator.hook_memory()` for MMIO simulation.
- `state.models` a collection of python models for library code implemented as
  customizable hooks.
- `state.debug` a collection of debug utilities that can be mapped into state.
- `fuzz()` AFL Unicorn fuzzing harness utility.
- `AngrEmulator` based on angr symbolic execution.
- `ELFImage` state object that loads an ELF file.
- `AngrNWBTAnalysis` unused value analysis using angr.
- `ControlFlowTracer` analysis that logs all jumps, calls, and returns.
- `CodeCoverage` analysis that maps program counter to hit count.
- `CodeReachable` analysis that show what code is reachable by symbolic execution.
- `Stack` initialization code to setup arguments.
- `PointerFinder` analysis that finds pointers.
- `ColorizerSummary` computes summary def use graph from colorizer.
- `setup_default_libc` use ghidra to add libc models at PLT entry points.
- `setup_section` use ghdira to add section from elf to cpustate.
- Emulation support for aarch64, arm32, mips, mips64 (angr only)


### Changed

- SH-1 and SH-2 ELF images (`e_flags` `EF_SH1` and `EF_SH2`) now load as
  `SUPERH_SH1` and `SUPERH_SH2` rather than `SUPERH_SH2A_FPU`, so they no
  longer run on Panda or Styx by default. Pass `platform` with
  `SUPERH_SH2A_FPU` to keep running them as SH-2A.
- `Value.{get, set}()` changed to `@property` `value`.
- `UnicornEmulator` captures more detailed error information in single step
  mode.
- `UnicornEmulator.write_memory()` now supports overlapping writes and no
  longer requires addresses to be page aligned.
- `Code.exits` changed to `Code.bounds` - ranges of valid execution rather than
  fixed exit points.
- `State.map()` automatically selects names for mapped objects when not
  provided.
- `Colorizer` replaces `InputColorizer`, extending analysis dramatically
- `State.models` to have lots more libc models.

## [0.0.1] - 2024-02-26

### Added

- Initial public SmallWorld demo.

[unreleased]: https://github.com/smallworld-re/smallworld/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/smallworld-re/smallworld/releases/tag/v0.0.1
