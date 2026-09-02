# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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

- MPC860 (PowerQUICC I) exception delivery and decrementer on the Styx backend
  (`cpu_model="mpc860"`). Upstream styx-emulator leaves the MPC866M event
  controller's `tick`/`latch`/`execute` as `todo!()`, so any run long enough to
  complete an instruction stride panicked and hung. The implementation is
  carried locally as `nix/styx-emulator-build/mpc860/` plus the patches in
  `nix/styx-emulator-build/patches/`; it covers exception entry (vector
  dispatch, MSR entry state, shadow SRR0/SRR1 with `rfi` interception) and a
  decrementer/timebase driven by the executor stride. Guest reads of SRR0/SRR1
  are not modelled, and the decrementer's resolution is the executor stride
  (1000 instructions), so it cannot represent a period shorter than that.
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
