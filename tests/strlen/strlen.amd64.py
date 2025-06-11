import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.X86_64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", "").replace(".panda", ""),
    address=0x1000,
)
machine.add(code)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.rip.set(code.address)

# Push a string onto the stack, padded to 16 bytes to make life easier.
# Remember the starting address
string = sys.argv[1].encode("utf-8") + b"\0"
padding = b"\0" * (16 - (len(string) % 16))
stack.push_bytes(string + padding, None)
print(stack)

saddr = stack.get_pointer()

print(hex(saddr))

# Push a return address
stack.push_integer(0x00000000, 8, None)

# Configure the stack
cpu.rsp.set(stack.get_pointer())

# Set the first argument to the stack address
cpu.rdi.set(saddr)

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.rip.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
cpu = final_machine.get_cpu()
print(hex(cpu.eax.get()))
