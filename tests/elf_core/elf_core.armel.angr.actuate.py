import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
# NOTE: Core dumps resolve as arm v7a.  Sorry.
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T, smallworld.platforms.Byteorder.LITTLE
)
coreplatform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V7A, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add core file into the state
filename = (
    __file__.replace(".actuate.py", ".elf.core")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf_core(
        f, platform=coreplatform
    )
    machine.add(code)
    code.populate_cpu(cpu)

# Load the original binary so we can copy .text
# I can't get my system to dump the executable segments.
origname = filename.replace(".core", "")
with open(origname, "rb") as f:
    orig = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)

# The core file reserves space before the true load address for its metadata.
code_offset = (cpu.pc.get() - code.address) & 0xFFFFFFFFFFFFF000
code[code_offset] = orig[0x0]

# Replace the instruction bytes at pc with a nop
nop = b"\xd5\x03\x20\x1f"
code.write_bytes(cpu.pc.get(), nop)

# Set up a puts handler
# puts address recovered from manual RE
puts_addr = (cpu.pc.get() & 0xFFFFFFFFFFFFF000) | 0x37C
puts = smallworld.state.models.Model.lookup(
    "puts", platform, smallworld.platforms.ABI.SYSTEMV, puts_addr
)
machine.add(puts)

# Add an exit point
# This is the ultimate return address
machine.add_exit_point(cpu.pc.get() + 0x14)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
machine.apply(emulator)
emulator.run()
