import logging
import struct
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V7A, smallworld.platforms.Byteorder.LITTLE
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
arg1 = int.from_bytes(struct.pack("d", float(sys.argv[1])), "little")
arg2 = int.from_bytes(struct.pack("d", float(sys.argv[2])), "little")

cpu.d0.set(arg1)
cpu.d1.set(arg2)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
machine.add_exit_point(cpu.pc.get() + code.get_capacity() - 4)
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
raw = cpu.d0.get()
(res,) = struct.unpack("d", raw.to_bytes(8, "little"))
print(f"{res}")
