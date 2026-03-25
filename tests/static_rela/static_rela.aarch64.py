import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.AARCH64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".o")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=0x400000
    )
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
print(f"Main: {hex(entrypoint)}")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
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

# Set argument registers, just in case.
cpu.x0.set(2)
cpu.x1.set(argv)

# Push a return address onto the stack
stack.push_integer(0x7FFFFFF8, 8, "fake return address")
machine.add_exit_point(0x7FFFFFF8)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure libc
libc = smallworld.state.models.c99.C99Libc(
    0x10000,
    platform,
    smallworld.platforms.ABI.SYSTEMV,
    allow_imprecise={"system", "atexit"},
)
libc.link(code)
machine.add(libc)

emulator = smallworld.emulators.UnicornEmulator(platform)
machine.emulate(emulator)
