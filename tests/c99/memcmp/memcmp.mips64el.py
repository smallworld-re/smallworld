import logging
import sys

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# Create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# Load and add code into the state
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".pcode", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
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
argv = stack.get_pointer()

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Set argument registers
cpu.a0.set(2)
cpu.a1.set(argv)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

memcmp_model = smallworld.state.models.Model.lookup(
    "memcmp", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(memcmp_model)
memcmp_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("memcmp", memcmp_model._address)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
machine.add(exit_model)
exit_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("exit", exit_model._address)


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure exits by dereferencing 0xdead.
# Catch the dereference
class DeadModel(smallworld.state.models.mmio.MemoryMappedModel):
    def __init__(self):
        super().__init__(0xDEAD, 1)

    def on_read(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, content: bytes
    ) -> bytes:
        raise FailExitException()

    def on_write(
        self, emu: smallworld.emulators.Emulator, addr: int, size: int, value: bytes
    ) -> None:
        pass


dead = DeadModel()
machine.add(dead)

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
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(entrypoint + 0x1000)
try:
    machine.emulate(emulator)
except FailExitException:
    if sys.argv[1] == "foobar":
        raise Exception("Test case reached failure case unexpectedly")
