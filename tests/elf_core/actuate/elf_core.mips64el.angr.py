import logging
import pathlib

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add core file into the state
filepath = pathlib.Path(__file__).resolve()
filename = (
    filepath.name.replace(".py", ".elf.core")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
filename = (filepath.parent.parent / filename).as_posix()
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf_core(f, platform=platform)
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
nop = b"\x00\x00\x00\x00"
code.write_bytes(cpu.pc.get(), nop)

# Set up a puts handler
# puts address recovered from manual RE
puts_addr = (cpu.pc.get() & 0xFFFFFFFFFFFFF000) | 0xC70
puts = smallworld.state.models.Model.lookup(
    "puts", platform, smallworld.platforms.ABI.SYSTEMV, puts_addr
)
machine.add(puts)

# Add an exit point
machine.add_exit_point(cpu.pc.get() + 0x30)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
# Extracting the machine state takes forever
machine.apply(emulator)
emulator.run()
