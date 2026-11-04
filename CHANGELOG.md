# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `GhidraEmulator` no longer drops a write to a fixed memory address. When an
  instruction stored to a constant address, which p-code expresses as a COPY
  into a memory varnode, the backend ran the write hooks and then skipped the
  op, so the store never happened.
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

- A prototype of the Intel 8051 (`Architecture.MCS51`) on the Ghidra backend,
  with `square`, `branch`, `mcs51_spaces` and `mcs51_flags` integration cases.
  The 8051's separate address spaces share one flat SmallWorld memory map,
  which `GhidraMachineDef.address_spaces` describes and the Ghidra emulator
  translates; `GhidraMachineDef.userops` lets a machine implement SLEIGH
  user-defined operations in Python, following the angr backend's Xtensa
  tables. Test binaries are assembled with SDCC. SmallWorld's Nix environment
  patches Ghidra's 8051 language (`nix/patches/ghidra-8051.patch`) so that
  arithmetic flags, bit addressing, `mov sp,#n` and `movx @Ri` behave as on
  hardware; `movx @Ri` takes the high byte of its address from P2, which SDCC
  pages external RAM through to initialize data and to reach pdata.
- The Intel 8051 on the angr backend, through angr's p-code engine. An 8051
  engine maps the 8051's address spaces onto the same flat map as the Ghidra
  backend and implements its user-defined operations, and the Nix
  environment applies the same 8051 patch to pypcode's copy of the language.
- The `dma`, `call`, `hooking`, `stack`, `static_buf`, `null_pc`,
  `exitpoint` and `unmapped` integration cases cover the 8051 on angr and
  Ghidra. `MCS51Stack` models its upward-growing stack in internal RAM, and
  `Model` returns from 8051 function hooks. angr machine definitions can
  supply `function_return_address` for a return address angr's calling
  conventions cannot describe; the 8051's lives in internal RAM.
- An `mcs51_diff` integration scenario that checks the 8051 against an
  independent simulator, SDCC's ucsim_51. Five programs covering arithmetic,
  logic, data movement, bit instructions and branches run from a random
  starting state, and their final registers, internal RAM, SFRs and XDATA are
  compared with the results `tests/mcs51_diff/generate.py` recorded from
  ucsim_51. They match on angr and Ghidra. A `paging` program checks
  `movx @Ri` across external RAM pages.
- The 8051's parity flag, PSW bit 0, on angr and Ghidra. Ghidra's 8051
  language never computes it, so both backends recompute it from the
  accumulator around every instruction; `GhidraMachineDef` gains
  `update_derived_state` for state a language leaves out.
- 8051 register banks on angr and Ghidra: R0-R7 follow the bank PSW's RS bits
  select in internal RAM 0x00-0x1F, so code that reaches them by address, as
  SDCC's does (`push ar7`), or switches banks runs as on hardware. The
  `mcs51_diff` scenario gains a `banks` program and compares all of internal
  RAM.
- SDCC's 8051 calling conventions, `ABI.SDCC` and `ABI.SDCCSTACKAUTO`, with
  C99 models for the functions SDCC's library provides, under
  `state.models.mcs51.sdcc` and `state.models.mcs51.sdccstackauto`. Models see
  SDCC's generic pointers as flat addresses. Under the default convention,
  where later arguments sit in each function's static memory, a model takes
  their addresses in `parameter_addresses`. The test binaries now include C
  built with SDCC, and the `mcs51_sdcc` scenarios check both conventions and
  run SDCC's own library with and without SmallWorld's models in its place.
- 8051 interrupts on angr and Ghidra. Between instructions, the CPU takes an
  enabled, requested interrupt whose priority beats those in service, as the
  hardware does, and `reti` ends its service. Harnesses request one by
  setting its flag, which `mcs51_raise_interrupt` does; timers, the serial
  port and pins are left to harness models. `GhidraMachineDef` gains
  `before_instruction`, which can redirect execution between instructions.
  The `mcs51_diff` scenario gains an `interrupts` program, and starts each
  program's PSW with parity that matches its accumulator.
- `Executable.from_ihex()` loads Intel HEX images. Given the ASxxxx linker
  map SDCC writes, the result looks up symbols with `get_symbol_value()`, as
  an ELF does; on the 8051, each symbol lands in its address space in
  SmallWorld's flat map.
- The C99 library-model tests run on the 8051, under both SDCC conventions,
  for the 44 functions with 8051 models. They build from the same sources as
  on other architectures, with a header that stands in for what SDCC's
  library lacks, and `tests/mcs51_runner.py` runs them. The 8051's
  `strerror` model gains the errno resolver it needed, and `rand` stays
  within SDCC's `RAND_MAX`, which `Rand.rand_max` now sets per C library.
  How `%p` shows a pointer is up to the calling convention, through
  `VariadicContext.format_next_pointer()`; on the 8051 it names the
  pointer's space as SDCC's library does (`X:0x002a`).

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

- The angr backend's 8051 engine keeps the register bank and the parity flag
  current incrementally: a full sync as each block starts, then only what
  each instruction wrote, with concrete values handled without the solver.
  Running SDCC's C library is about five times faster.
- The Ghidra backend records what each instruction, hook, model or harness
  writes, and `GhidraMachineDef.update_derived_state` receives the record,
  so the 8051's register bank sync, parity flag and interrupt checks act
  only on what changed. Running SDCC's C library is about three times
  faster.
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
