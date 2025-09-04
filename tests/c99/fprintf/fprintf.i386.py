import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

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
filename = (
    __file__.replace(".py", ".elf")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".ghidra", "")
)
with open(filename, "rb") as f:
    code = smallworld.state.memory.code.Executable.from_elf(
        f, platform=platform, address=0x400000
    )
    machine.add(code)

# Set the entrypoint to the address of "main"
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x8000, 0x4000)
machine.add(stack)

# Push a string onto the stack
string = "".encode("utf-8")
string += b"\0"
string += b"\0" * (16 - (len(string) % 16))

stack.push_bytes(string, None)
str_addr = stack.get_pointer()

# Push argv
stack.push_integer(0, 4, None)  # NULL terminator
stack.push_integer(str_addr, 4, None)  # pointer to string
stack.push_integer(0x10101010, 4, None)  # Bogus pointer to argv[0]
argv = stack.get_pointer()

# Push arguments onto stack
stack.push_integer(argv, 4, None)
stack.push_integer(2, 4, None)

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 4, "fake return address")


# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

fprintf_model = smallworld.state.models.Model.lookup(
    "fprintf", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(fprintf_model)
fprintf_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("fprintf", fprintf_model._address)

puts_model = smallworld.state.models.Model.lookup(
    "puts", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
machine.add(puts_model)
puts_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("puts", puts_model._address)


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure exitss by dereferencing 0xdead.
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

# Emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(entrypoint + 0x2000)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except FailExitException:
    pass
