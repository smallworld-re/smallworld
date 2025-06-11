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
filename = __file__.replace(".py", ".elf").replace(".angr", "").replace(".panda", "")
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set entrypoint from the ELF
if code.entrypoint is None:
    raise ValueError("ELF has no entrypoint")
cpu.rip.set(code.entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Push a string onto the stack
string = sys.argv[1].encode("utf-8")
string += b"\0"
string += b"\0" * (16 - (len(string) % 16))

stack.push_bytes(string, None)
str_addr = stack.get_pointer()

# Push argv
stack.push_integer(0, 8, None)  # NULL terminator
stack.push_integer(str_addr, 8, None)  # pointer to string
stack.push_integer(0x10101010, 8, None)  # Bogus pointer to argv[0]

# Push address of argv
argv = stack.get_pointer()
stack.push_integer(argv, 8, None)

# Push argc
stack.push_integer(2, 8, None)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.rsp.set(sp)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)

# Use code bounds from the ELF
emulator.add_exit_point(0)
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

# I happen to know that the code _actually_ stops
# at .text + 0x2d
emulator.add_exit_point(bound[0] + 0x2D)

machine.emulate(emulator)
