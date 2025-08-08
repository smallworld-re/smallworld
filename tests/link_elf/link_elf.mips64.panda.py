import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS64, smallworld.platforms.Byteorder.BIG
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = __file__.replace(".py", ".elf").replace(".panda", "").replace(".pcode", "")
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

libname = __file__.replace(".py", ".so").replace(".panda", "").replace(".pcode", "")
with open(libname, "rb") as f:
    lib = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=0x400000
    )
    machine.add(lib)

code.link_elf(lib)

# Load and add code from lib.
# Pray to pudding that

# Set entrypoint from the ELF
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

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
cpu.sp.set(sp)

# Set argument registers
cpu.a0.set(2)
cpu.a1.set(argv)

# UTTER AND TOTAL MADNESS
# MIPS relies on a "Global Pointer" register
# to find its place in a position-independent binary.
# In MIPS64, this is computed by relying on
# the fact that dynamic function calls use
# the t9 register to store the address of the target function.
#
# The function prologue sets gp to t9 plus a constant,
# creating an address that's... not in the ELF image...?
# Position-independent references then subtract
# larger-than-strictly-necessary offsets
# from gp to compute the desired address.
#
# TL;DR: To call main(), t9 must equal main.
cpu.t9.set(entrypoint)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)

# Use code bounds from the ELF
emulator.add_exit_point(0)
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])
for bound in lib.bounds:
    machine.add_bound(bound[0], bound[1])

# I happen to know where the code _actually_ stops
emulator.add_exit_point(entrypoint + 0x84)

final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()

print(final_cpu.v0)
