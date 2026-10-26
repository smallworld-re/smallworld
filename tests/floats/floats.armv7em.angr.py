import logging
import struct
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V7EM, smallworld.platforms.Byteorder.LITTLE
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
    .replace(".pcode", ""),
    address=0x1000,
)
machine.add(code)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
# FPv4-SP is single-precision only, so these are floats, not doubles.
arg1 = int.from_bytes(struct.pack("f", float(sys.argv[1])), "little")
arg2 = int.from_bytes(struct.pack("f", float(sys.argv[2])), "little")

cpu.s0.set(arg1)
cpu.s1.set(arg2)

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
raw = cpu.s0.get()
(res,) = struct.unpack("f", raw.to_bytes(4, "little"))
print(f"{res}")
