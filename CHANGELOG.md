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
- On angr, a function hook that moves the program counter carries on there
  instead of returning to the hook's caller, so a model can call back into
  the program, as `qsort` and `bsearch` do with their comparator. A hook that
  set the program counter to its return address, counting on angr to pop
  it, must now pop it itself, as on the other backends.
- `GhidraEmulator` runs memory write hooks only for stores to the address
  spaces SmallWorld maps, not for a store some language makes to another
  space.
- `GhidraEmulator` no longer drops a write to a fixed memory address. When an
  instruction stored to a constant address, which p-code expresses as a COPY
  into a memory varnode, the backend ran the write hooks and then skipped the
  op, so the store never happened.
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
- The p-code use/def analysis no longer misreads MIPS32 code above a `jalx`
  target that it analyzed after the `jalx`. Decoding a `jalx` left its cached
  SLEIGH context decoding those addresses as MIPS16, so their reads and
  writes came back empty or wrong; the context is now rebuilt after one.
- `Memory` state objects with large values are now stringified much faster.
- `InputColorizerAnalysis` can now handle 32-bit cpu.
- `TritonEmulator` no longer returns from a hooked function twice; the hook
  itself performs the return, as it does on every other backend.
- `TritonEmulator` reports unmapped fetches, reads and writes instead of
  silently succeeding on Triton's flat, lazy memory.
- `TritonEmulator` no longer raises a spurious memory-read hook for the
  destination of an ARM32 store.
- RISC-V (lp64d) C models read and write a floating-point argument that
  finds no FP argument register in the next integer register, as the psABI
  passes it, rather than on the stack.
- RISC-V compressed instructions disassemble: the platform's capstone mode
  includes the "C" extension, which `TraceExecution`, crash triage and
  Unicorn's fault reports need; and capstone's names for branches against
  zero (`beqz`, `c.bnez`...) count as conditional branches.
- On RISC-V, `TritonEmulator` raises an interrupt for `c.ebreak`, as for
  `ebreak`, and steps past `fence`, `fence.i`, `fence.tso` and `pause`;
  `GhidraEmulator` steps past `fence` and `fence.i`, which the RISC-V
  machine definitions list in `GhidraMachineDef.nop_userops`.  Both stopped
  with an error.
- The RISC-V ELF relocator resolves TLS module and offset relocations
  (`R_RISCV_TLS_DTPMOD64`, `R_RISCV_TLS_DTPREL64`) and names what is missing
  for `R_RISCV_COPY` and `R_RISCV_TLS_TPREL64`, rather than calling them
  unknown.
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
- PowerPC64's calling context sets `r12` to the callee's address when
  `FunctionPointer` calls a guest function, through `begin_call()`, as an
  ELFv2 global entry point expects for finding the TOC.
- `interrupt`, `fuzz` (including AFL) and `static_rela` integration cases for
  PowerPC64.
- `elf_core` integration cases for PowerPC64. Its test binary is built with
  Nix's ELFv2 cross gcc rather than zig, whose `powerpc64-linux-gnu` target
  binds ELFv1 glibc symbol versions that the ELFv2 glibc used for the core
  dump does not provide.
- `PPC64Instruction`, so analyses can decode PowerPC64; and PowerPC64 support
  in the malloc field-detection model. The `memhook` integration cases now
  cover ppc64.
- 32-bit RISC-V (`Architecture.RISCV32`, modeled as RV32GC): platform
  definition, CPU, stack, errno, ELF loading and relocation, ilp32d System V
  library models, plus machine definitions for the Unicorn, angr (via pcode),
  Ghidra and Triton emulators. The integration harness and test binaries cover
  `riscv32` everywhere they cover `riscv64`. ilp32d C models pass a fixed
  8-byte argument in the next two argument registers, split between `a7` and
  the stack when only `a7` is left, and a floating-point argument with no FP
  register left in integer registers, as the psABI does.
- A prototype of the Intel 8051 (`Architecture.MCS51`) on the Ghidra backend,
  with `square`, `branch`, `mcs51_spaces` and `mcs51_flags` integration cases.
  The 8051's separate address spaces share one flat SmallWorld memory map,
  which `GhidraMachineDef.address_spaces` describes and the Ghidra emulator
  translates; its `decimal_adjust` userop runs through
  `GhidraMachineDef.userops`, and its `nop` through `nop_userops`. Test binaries are assembled with SDCC. SmallWorld's Nix environment
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
  refuses a region outside it, and
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
  program's PSW with parity that matches its accumulator. On angr, a block
  also ends around any instruction a hook or memory-mapped model may run at,
  so that hooks see the register bank, parity and paging current, and an
  interrupt they raise is taken at the next instruction, as on Ghidra;
  state that decides how the 8051 runs, such as an interrupt SFR, raises
  `SymbolicValueError` if it is symbolic.
  `GhidraSymbolicEmulator` refuses the 8051, whose address spaces and user
  operations it does not implement.
- `Executable.from_ihex()` loads Intel HEX images. Given the ASxxxx linker
  map SDCC writes, the result looks up symbols with `get_symbol_value()`, as
  an ELF does, and `get_map_value()` returns a symbol's value as the map
  records it. Where the image and symbols land is up to the platform's
  `IHexLayout`: on the 8051 (`MCS51IHexLayout`), each symbol lands in its
  address space in SmallWorld's flat map, and the image must fit the 64 KiB
  of code space.
- The C99 library-model tests run on the 8051, under both SDCC conventions,
  in SDCC's small and large memory models and, under the default convention,
  its medium one, for the functions with 8051 models.  An 8051 model that
  returns a pointer into a pdata pointer argument's object - the nearest
  pointer argument at or below it, in the same page - returns a pdata
  pointer, as SDCC would, rather than an XDATA one to the same byte, which
  SDCC compares as different. They build from the same sources as on other
  architectures, with stubs, built as a module of their own, for what SDCC's
  library lacks, and `tests/mcs51_runner.py` runs them, failing a test whose
  function's model never runs, since SDCC's own library would run instead.
  The 8051's `strerror` model gains the errno resolver it needed, and `rand`
  stays within SDCC's `RAND_MAX`, which `Rand.rand_max` now sets per C
  library.
  How `%p` shows a pointer is up to the calling convention, through
  `VariadicContext.format_next_pointer()`; on the 8051 it names the
  pointer's space as SDCC's library does (`X:0x002a`), without padding it to
  a field width; and, as SDCC's library has no `%n`, it prints `N` there and
  takes no argument. Elsewhere, `%n` writes the count through the calling
  convention, as an `int` of its size and byte order.
- `qsort` and `bsearch` models for the 8051, which call the program's
  comparator back with SDCC's reentrant convention, as SDCC's library does.
  A calling context now hands models a function pointer with the right
  convention, through `CStdCallingContext.function_pointer()`, and sets up
  and cleans up each call, through `begin_call()` and `end_call()`; the
  8051's makes room for stack arguments below the return address and pops
  them afterwards.
- Silicon Labs' CIP-51 devices, emulated as an 8051. The 8051's new
  `xpage_sfr` register names the SFR that supplies the high byte of
  `movx @Ri`'s address: P2, as before, unless the harness sets it to the
  device's EMI0CN. `movx @Ri` takes the page from the `xpage` register,
  which the emulators keep in step with that SFR, or at 0 where it is not
  mapped. 8051 models read pdata pointers in that page, as SDCC's library
  does, rather than always in XDATA's first page.
  Machine definitions on Ghidra and angr can set initial state through
  `initialize_state()`. `mcs51_sdcc` builds for the C8051F330 and the
  C8051F020, whose EMI0CN are at 0xAA and 0xAF, test it.
- `mcs51_xpage_sfr()` looks up the SFR that pages `movx @Ri` on an 8051
  device by part number, for Silicon Labs' CIP-51 families and the other
  devices SDCC's headers declare one for. An image loaded with
  `Executable.from_ihex()` reports the same SFR from an SDCC linker map's
  `__XPAGE`, through `get_map_value("__XPAGE")`.
- `MCS51Device`, added to a machine, emulates an 8051 device: it sets
  `xpage_sfr` and makes the Ghidra and angr emulators take the device's
  interrupts rather than the 8052's. A device whose interrupts are not
  tabulated takes the 8052's, with a warning. The C8051F330-F335's are, as
  `C8051F33xInterrupt`, with their EIE1 and EIP1 enables and priorities and
  the second enable bits some of their flags need; an `mcs51_sdcc` program
  built for the C8051F330 tests them. Interrupt sources are now an
  `MCS51InterruptSource` enum per device, of which `MCS51Interrupt` is the
  8052's, and `mcs51_interrupt_to_take()` and `mcs51_service_interrupts()`
  take the device's sources.
- Silicon Labs' paged SFRs, for the C8051F04x, F06x, F12x/F13x and F36x: an
  `MCS51Device` for one has SFRs on the page SFRPAGE selects, and takes
  interrupts through the SFR page stack. SFRs are now in a space with a page above each SFR, `PSFR`, whose
  page 0 is where SFRs were; Ghidra's bit space moves to 0x30100. The 8051
  language's patch adds the space and the registers that page it,
  `sfr_page`, `sfr_paged_lo` and `sfr_paged_hi`. `mcs51_sdcc` programs built
  for the C8051F040, F060, F120 and F360 test it, and the C8051F040's EMI0CN,
  at 0xA2.
- Silicon Labs' flash programming, for the C8051F330-F335: an `MCS51Device`
  for one sends MOVX writes to flash while PSCTL's PSWE is set, writing or
  erasing it once FLKEY is unlocked, as the data sheet describes. Ghidra
  machine definitions can perform an instruction's store themselves, through
  `redirect_store()`. An `mcs51_sdcc` program built for the C8051F330 tests
  it.
- Silicon Labs' EFM8BB2: `mcs51_xpage_sfr()` knows its EMI0CN, at 0xE7, and
  an `MCS51Device` for it writes its flash, from `MCS51_EFM8BB2_FLASH`, as
  its reference manual describes. `MCS51FlashProgramming` takes regions of
  flash whose pages are another size, as the EFM8BB2's 64-byte pages at
  0xF800-0xFBFF are. `mcs51_sdcc` programs built for it, with
  `tests/mcs51_sdcc/efm8bb2.h` in place of the device header SDCC lacks,
  test it.
- The EFM8BB2's paged SFRs: an `MCS51Device` for it pages them from
  `MCS51_EFM8BB2_SFR_PAGING`, taken from its reference manual, with SFRs on
  page 0 and one other page as well, and a five-level page stack that
  firmware reads through SFRSTACK. `MCS51SFRPaging` gains `also_shared`, for
  SFRs on some pages but not all, whose `paged_masks()` depend on the page,
  and `stack_view`, for a stack read through an SFR; its `sfrnext` and
  `sfrlast` become `stack`, the levels below SFRPAGE. `mcs51_sfr_stack_view()`
  says what that SFR reads. The emulators warn, once, when a device's
  paging is not modeled because SFRs it depends on are not mapped. An
  `mcs51_sdcc` program built for the EFM8BB2 tests it.
- The EFM8BB2's interrupts, as `EFM8BB2Interrupt`, from its reference
  manual, with four priority levels. An `MCS51InterruptSource` takes the SFR
  of its priority's high bit, `priority_high_sfr`, and request flags in
  other SFRs, `other_flags`; `level()` and `page()` say its priority and the
  SFR page taking it selects. `mcs51_raise_interrupt()` refuses a source
  with no request flag, as the EFM8BB2's Port Match is. An `mcs51_sdcc`
  program built for the EFM8BB2 tests them.

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
  (concrete) backends. `pc` is the linear address `cs * 16 + ip`. angr and
  Ghidra use Ghidra's real-mode language, which only handles code segments
  that start on a 64 KiB boundary, and which ignores segments in a few
  instructions; Unicorn handles any segment, but not far returns. See the
  platform support notes. `X86RealModeStack` gives the `ss:sp` for its
  stack, and `x86RealModeInstruction` decodes real-mode instructions for
  the analyses.
- `UnicornMachineDef.pc_from_engine()`/`pc_to_engine()`, for machines whose
  program counter register is not the linear pc.
- `GhidraMachineDef.nop_userops` and `GhidraMachineDef.userops`, for sleigh
  user ops that Ghidra's emulator does not provide: the first names userops
  to step over, and the second maps a userop's name to a function of the
  emulator, the instruction's mnemonic and the userop's arguments that
  returns its output. `GhidraEmulator` and `GhidraSymbolicEmulator` both use
  them. `GhidraMachineDef.ram_address_size`, for machines whose RAM offsets
  are wider than their pointers.
- `PlatformDef.isa_bit`, an `IsaBit`, says what bit 0 of a code address
  means: part of the address, or the choice between a CPU's two instruction
  sets (ARM's Thumb bit, MIPS's ISA bit). `Emulator.get_isa_mode()` and
  `Emulator.set_isa_mode()` read and choose the instruction set on platforms
  with two. A function model placed at an odd address on such a platform
  hooks the even one, and returns to the instruction set that bit 0 of its
  return address selects, where the backend can switch.
- ARM's 32-bit platforms use the ISA-mode API: `isa_bit` is `SELECTS` where
  the CPU has Thumb, `REQUIRED` on M-profile, which runs only Thumb, and
  `NONE` on ARMv4. `PlatformDef.isa_mode_register` names the register bit
  that holds the mode, cpsr's T bit on ARM, which `get_isa_mode()` and
  `set_isa_mode()` read and write; on M-profile they report Thumb and refuse
  ARM. `PandaEmulator` and `TritonEmulator`, whose cpsr doesn't hold the T
  bit, reach the mode through their own Thumb state, PANDA through the new
  `PandaMachineDef.read_isa_mode()` and `write_isa_mode()`.
- `AngrEmulator` keeps no Thumb code of its own: `AngrMachineDef` gains
  `pc_from_engine()`, the inverse of `pc_to_engine()`, `code_addresses()`,
  the addresses angr may reach an instruction at, which hooks and exit
  points cover, and `read_isa_mode()` and `write_isa_mode()`, for a mode
  angr keeps outside the platform's register (ARM: bit 0 of pc). Writing an
  odd pc on a platform whose `isa_bit` is `SELECTS` selects the alternate
  instruction set, as on Ghidra, and a mode set before initialization takes
  effect once the emulator has a state.
- `UnicornEmulator` and the Ghidra emulators keep no Thumb code of their
  own either. `UnicornMachineDef.disassembler_mode()` picks the capstone mode
  for the instruction set the CPU runs, and ARM's Unicorn `pc_to_engine()`
  keeps the Thumb bit that `emu_start()` and a pc write take the mode from.
  Writing an odd pc to Unicorn on a `SELECTS` platform selects the alternate
  instruction set. On ARMv4, which has no Thumb, `get_thumb()` and
  `set_thumb()` now raise `ConfigurationError`, as the ISA-mode API does.
- Machine-definition hooks that convert SmallWorld's pc to the backend's:
  `AngrMachineDef.pc_to_engine()` and `GhidraMachineDef.pc_to_engine()`, for
  pc writes, and `UnicornMachineDef.pc_to_start()`, for the address
  `emu_start()` begins at, which `Machine.fuzz()` also starts unicornafl runs
  at.
- `Architecture.MIPS32_MICROMIPS`, MIPS32 with the microMIPS encoding, big-
  and little-endian. Ghidra switches between microMIPS and standard MIPS32 as
  hardware does; angr and Unicorn run microMIPS only. An `isa_mode`
  pseudo-register holds the current encoding, and an odd pc selects microMIPS.
  ELF images flagged `EF_MIPS_MICROMIPS` load as this platform, with a warning
  if their symbols show standard MIPS32 functions too. Its code addresses
  keep the ISA bit: the entrypoint, microMIPS code symbols and pointers
  relocated to them are odd. Machine-definition hooks carry the mode:
  `GhidraMachineDef.context` sets starting context fields,
  `GhidraMachineDef.isa_bit_context` names the field an odd pc selects, and
  the pc hooks below set Unicorn's ISA bit and store an even pc on angr and
  Ghidra. The Ghidra emulators read and write sleigh context fields as
  registers. The
  System V C and POSIX models cover microMIPS as they do MIPS32. The p-code
  use/def analysis covers it too: `PlatformDef.ghidra_context` names the
  context values a platform's code decodes with, and
  `pcode_use_def.analyze()` takes them. PANDA has no microMIPS support.
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
- TLS descriptor state moves from `ElfExecutable` to the relocator, which
  alone knows the architecture's descriptor ABI. `ElfRelocator` gains generic
  `tls_descriptors` and `bind_tls_descriptor_resolver()` hooks, implemented by
  `AMD64ElfRelocator`; `ElfExecutable.relocator` exposes an image's relocator,
  and `ElfExecutable.reserve_synthetic()` reserves space past the loaded image
  for what a linker would have built. `ElfRelocator.synthetic_slot()` gives a
  relocator one such slot per key, idempotently, as for an object file's
  descriptor slots. `ElfExecutable.tlsdesc_descriptors`, `bind_tlsdesc_resolver()`,
  `tlsdesc_got_slot()` and `note_tlsdesc_descriptor()` are gone. An
  `ElfExecutable` pickled by an earlier version no longer unpickles.

### Deprecated

- `Emulator.get_thumb()` and `Emulator.set_thumb()`, in favor of
  `get_isa_mode()` and `set_isa_mode()`, which they now call: Thumb is mode
  1, ARM mode 0. They raise `DeprecationWarning`. The backends' own
  versions are gone.

## [0.0.1] - 2024-02-26

### Added

- Initial public SmallWorld demo.

[unreleased]: https://github.com/smallworld-re/smallworld/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/smallworld-re/smallworld/releases/tag/v0.0.1
