import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_32, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    "strlen.i386.bin", address=0x1000
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.eip.set(code.address)

# Push a string onto the stack, padded to 16 bytes to make life easier.
# Set the first argument as the starting address
string = sys.argv[1]
padding = b"\0" * (16 - (len(string) % 16))
stack.push_bytes(string.encode("utf-8") + padding, None)

saddr = stack.get_pointer()
stack.push_integer(saddr, 4, None)

# Push a return address
stack.push_integer(0x00000000, 4, None)

# Configure the stack
cpu.esp.set(stack.get_pointer())

# Emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.eip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.eax.get()))
