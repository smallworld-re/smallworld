import logging
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

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Push a string onto the stack, padded to 16 bytes to make life easier.
# Remember the starting address
string = sys.argv[1].encode("utf-8") + b"\0"
padding = b"\0" * (16 - (len(string) % 16))
stack.push_bytes(string + padding, None)

saddr = stack.get_pointer()

# Push a return address
stack.push_integer(0x00000000, 4, None)

# Configure the stack
cpu.sp.set(stack.get_pointer())

# Set the first argument to the stack address
cpu.r0.set(saddr)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
machine.add_exit_point(cpu.pc.get() + code.get_capacity() - 4)
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.r0.get()))
