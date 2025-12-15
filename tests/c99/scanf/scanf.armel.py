import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V6M, smallworld.platforms.Byteorder.LITTLE
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

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

scanf_model = smallworld.state.models.Model.lookup(
    "scanf", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(scanf_model)
scanf_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("__isoc99_scanf", scanf_model._address)

printf_model = smallworld.state.models.Model.lookup(
    "printf", platform, smallworld.platforms.ABI.SYSTEMV, 0x10008
)
machine.add(printf_model)
printf_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("printf", printf_model._address)

puts_model = smallworld.state.models.Model.lookup(
    "puts", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
machine.add(puts_model)
puts_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("puts", puts_model._address)

strcmp_model = smallworld.state.models.Model.lookup(
    "strcmp", platform, smallworld.platforms.ABI.SYSTEMV, 0x10010
)
machine.add(strcmp_model)
strcmp_model.allow_imprecise = True

# Relocate strcmp
code.update_symbol_value("strcmp", strcmp_model._address)

ungetc_model = smallworld.state.models.Model.lookup(
    "ungetc", platform, smallworld.platforms.ABI.SYSTEMV, 0x10014
)
machine.add(ungetc_model)
ungetc_model.allow_imprecise = True

# Relocate ungetc
code.update_symbol_value("ungetc", ungetc_model._address)

getc_model = smallworld.state.models.Model.lookup(
    "getc", platform, smallworld.platforms.ABI.SYSTEMV, 0x1001C
)
machine.add(getc_model)
getc_model.allow_imprecise = True

# Relocate getc
code.update_symbol_value("getc", getc_model._address)

strlen_model = smallworld.state.models.Model.lookup(
    "strlen", platform, smallworld.platforms.ABI.SYSTEMV, 0x10018
)
machine.add(strlen_model)
strlen_model.allow_imprecise = True

# Relocate strlen
code.update_symbol_value("strlen", strlen_model._address)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10020
)
machine.add(exit_model)
exit_model.allow_imprecise = True

# Relocate exit
code.update_symbol_value("exit", exit_model._address)


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
emulator.add_exit_point(entrypoint + 0x10000)
try:
    machine.emulate(emulator)
except FailExitException:
    if "" == "foobar":
        raise Exception("Test case reached failure case unexpectedly")
