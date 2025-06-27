.. _platforms:

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

.. csv-table:: Basic ISA Support
    :file: basic_isa_support.csv
    :header-rows: 1
    :stub-columns: 1

Specific Emulator Notes
=======================

- angr is strictly a user-space emulator.  It models very few, if any, privileged features of a processor.
- Ghidra's language models are written more for static analysis than execution, so the fidelity of the various ISA models varies drastically.  Usually, they are user-space only, and may only implement approximations of certain complex instructions.
- Unicorn is a user-space emulator running on top of a full-system emulator (QEMU).  Privileged options may have unexpected effects or even crash the emulator.  Advanced users familiar with unicorn can unlock the full-system emulation features, but this is not supported directly by SmallWorld.

Specific ISA Notes
==================

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

**xtensa:** The Xtensa ISA is made up of a core feature set, a number of open ISA options,
and some proprietary extensions introduced by the manufacturer.
Our emulation support depends on Ghidra's hardware model,
which only handles part of the open ISA options.  
In particular, it does _not_ handle all options and extensions used by the esp32 series of SoCs.
You will run into untranslatable instruction errors.

**Register Windows:** Some ISAs - SPARC64 and some Xtensa variants -
save and restore call frames by changing how the general purpose registers alias the register file.  
Compare this to how most other architectures push and pop registers from the stack.  
Windowed architectures are impossible to emulate in a userspace-only emulator, 
since they use interrupts to "spill" registers onto the stack if there are more call frames 
than they have windows.  Currently, only angr and ghidra support the relevant ISAs;
until that changes, SmallWorld cannot support windowed ISAs.

Floating Point and Vector Support
=================================

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

