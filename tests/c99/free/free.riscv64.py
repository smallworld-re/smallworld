import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.RISCV64, smallworld.platforms.Byteorder.LITTLE
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
        f, platform=platform, address=0x40000
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

malloc_model = smallworld.state.models.Model.lookup(
    "malloc", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
malloc_model.heap = heap
machine.add(malloc_model)
malloc_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("malloc", malloc_model._address)

free_model = smallworld.state.models.Model.lookup(
    "free", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
free_model.heap = heap
machine.add(free_model)
free_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("free", free_model._address)


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure frees by dereferencing 0xdead.
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
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(entrypoint + 0x1000)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except FailExitException:
    pass
