import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.LITTLE
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

# Push a return address onto the stack
stack.push_integer(0xFFFFFFFF, 8, "fake return address")

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Configure the heap
heap = smallworld.state.memory.heap.BumpAllocator(0x20000, 0x1000)
machine.add(heap)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
machine.add(exit_model)
exit_model.allow_imprecise = True

# Relocate putchar
code.update_symbol_value("exit", exit_model._address)

putchar_model = smallworld.state.models.Model.lookup(
    "putchar", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
machine.add(putchar_model)
putchar_model.allow_imprecise = True

# Relocate putchar
code.update_symbol_value("putchar", putchar_model._address)


# Relocate putchar

# Set FS model to active
fdmgr = smallworld.state.models.filedesc.FileDescriptorManager.for_platform(
    platform, smallworld.platforms.ABI.SYSTEMV
)
fdmgr.model_fs = True
stdin = fdmgr.open("stdout", False, True, True, False, False, False)
fdmgr._fds[1] = fdmgr._fds[stdin]


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure putchars by dereferencing 0xdead.
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
emulator.add_exit_point(entrypoint + 0x1000)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except FailExitException:
    pass
res = fdmgr.get_file("stdout")
res.seek(0)
expected = b"f"
actual = res.read()

if expected != actual:
    raise Exception(f"Expected stdout to contain {expected!r}; got {actual!r}")
