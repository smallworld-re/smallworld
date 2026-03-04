import logging
import pathlib

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
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

# Replace the instruction bytes at pc with a nop
nop = b"\x66\x90"
code.write_bytes(cpu.pc.get(), nop)

# Set up a puts handler
# puts address recovered from manual RE
puts_addr = (cpu.pc.get() & 0xFFFFFFFFFFFF0000) | 0x10A0
puts = smallworld.state.models.Model.lookup(
    "puts", platform, smallworld.platforms.ABI.SYSTEMV, puts_addr
)
machine.add(puts)

# Nuke the segment registers
cpu.cs.set(0)
cpu.ss.set(0)
cpu.ds.set(0)
cpu.es.set(0)
cpu.fs.set(0)
cpu.gs.set(0)

# Add an exit point
machine.add_exit_point(cpu.pc.get() + 0x22)

# Emulate
emulator = smallworld.emulators.GhidraEmulator(platform)
machine.emulate(emulator)
