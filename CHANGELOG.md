# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- An exception while `PandaEmulator` sets up its CPU (PANDA's machine-init
  callback) is raised from the constructor rather than leaving it waiting
  forever.
- `UnicornEmulator` runs PowerPC64. SmallWorld's Unicorn build is patched so
  an explicit PPC64 CPU model selects that model instead of a PPC32 one, and so
  PPC64 CPUs start in hypervisor mode instead of faulting on their first
  instruction fetch. `PPC64MachineDef` now warns only when the loaded Unicorn
  lacks those patches.
- `UnicornEmulator` enables the PowerPC floating-point, vector and VSX
  facilities, so floating-point code no longer raises a facility-unavailable
  interrupt.
- PowerPC64 ELFv2 binaries relocate: `R_PPC64_JMP_SLOT` is a plain `S + A`
  there. ELFv1 binaries, whose PLT slots hold function descriptors, still raise
  `NotImplementedError`. `ElfExecutable.processor_flags` records the header's
  `e_flags`.
- PowerPC64 relocatable objects (`.o`) load: the TOC-relative, PC-relative
  and `bl` relocations a compiler emits are applied, and the linker-defined
  `.TOC.` symbol is set to the TOC base.
  As GNU ld does, the TOC base is 0x8000 past `.got`, `.toc`, or failing
  those the first writable section, and an ELFv2 `bl` enters its callee at
  the local entry point, past the prologue that sets `r2` from `r12`.
  `ElfSymbol.other` keeps the whole `st_other` byte. Relocators get two
  generic hooks for what a linker would create, `ElfRelocator.prepare_object`
  and `ElfRelocator.linker_symbol_value`, so this lives in the PowerPC64
  relocator rather than in `ElfExecutable`.
- ELF symbol visibility is read from the low two bits of `st_other`, so
  PowerPC64 ELFv2 local-entry bits no longer produce an invalid visibility.
- A `float` argument passed by a model on PowerPC is rounded to single precision
  before being written in double format; PowerPC's `stfs` truncates anything
  more precise.
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

- `floats` and `testfloat` integration cases for 32- and 64-bit PowerPC. Unicorn
  passes all ten TestFloat functions; Ghidra skips single-precision multiply
  and divide for its known subnormal flush; angr runs double precision only,
  since it implements none of the VEX ops PowerPC single precision lowers to.
  `PandaEmulator` turns on the PowerPC floating-point and vector facilities,
  which QEMU's system-mode reset leaves off (`PandaMachineDef.configure_cpu`);
  32-bit PowerPC then passes all but square root, which PANDA's PowerPC 604
  lacks. PowerPC64 under PANDA has not yet been measured.
- `PandaEmulator` runs PowerPC64, as a POWER8. SmallWorld's PANDA build is
  patched to build QEMU's configurable machine for the ppc64 target, and a
  machine check, which is how the CPU reports an unmapped instruction fetch,
  raises `EmulationFetchUnmappedFailure`.
- PowerPC64 ELFv2 System V library models (`smallworld.state.models.powerpc64`),
  with the ELFv2 rules that a floating-point argument uses up its
  general-purpose register slot, that an `int` argument fills its doubleword
  extended by signedness, and that a `float` past `f13` is a single in the
  second word of its stack slot, as GCC and clang place them. The c99/posix,
  `sysv`, `funcptr`, `checked_heap`, `rela` and `link_elf` integration cases
  now cover ppc64.
- `CStdCallingContext.enter_function()`, which `FunctionPointer` uses to jump
  to a guest function; on PowerPC64 it also sets `r12` for the TOC.
- `interrupt`, `fuzz` (including AFL) and `static_rela` integration cases for
  PowerPC64.
- `elf_core` integration cases for PowerPC64. Its test binary is built with
  Nix's ELFv2 cross gcc rather than zig, whose `powerpc64-linux-gnu` target
  binds ELFv1 glibc symbol versions that the ELFv2 glibc used for the core
  dump does not provide.
- `PPC64Instruction`, so analyses can decode PowerPC64; and PowerPC64 support
  in the malloc field-detection model. The `memhook` integration cases now
  cover ppc64.
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
