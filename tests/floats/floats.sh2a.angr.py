import logging
import struct
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.SUPERH_SH2A_FPU,
    smallworld.platforms.Byteorder.BIG,
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
    .replace(".styx", ""),
    address=0x1000,
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# SuperH takes its floating-point precision from FPSCR rather than from the
# opcode, so this has to be set before entry.  0x00040000 is the reset value
# with PR=0 (single precision) and RM=00 (round to nearest); the reset default
# of 0x00040001 selects round-to-zero, which would turn 3.3000002 into
# 3.2999998 and lose the "3.3" this scenario asserts on.
cpu.fpscr.set(0x00040000)

# Initialize argument registers.  Single precision, so fr0/fr2 rather than
# fr0/fr1: fr0 and fr1 are the two halves of dr0, and writing both would be
# writing one register twice.
arg1 = int.from_bytes(struct.pack(">f", float(sys.argv[1])), "big")
arg2 = int.from_bytes(struct.pack(">f", float(sys.argv[2])), "big")

cpu.fr0.set(arg1)
cpu.fr2.set(arg2)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
raw = cpu.fr0.get()
(res,) = struct.unpack(">f", (raw & 0xFFFFFFFF).to_bytes(4, "big"))
print(f"{res}")
