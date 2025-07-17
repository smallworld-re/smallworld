import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.ARM_V5T, smallworld.platforms.Byteorder.LITTLE
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

# Configure the heap
heap = smallworld.state.memory.heap.BumpAllocator(0x20000, 0x1000)
machine.add(heap)

exit_model = smallworld.state.models.Model.lookup(
    "exit", platform, smallworld.platforms.ABI.SYSTEMV, 0x10004
)
exit_model.heap = heap
machine.add(exit_model)
exit_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("exit", exit_model._address)

memset_model = smallworld.state.models.Model.lookup(
    "memset", platform, smallworld.platforms.ABI.SYSTEMV, 0x10000
)
memset_model.heap = heap
machine.add(memset_model)
memset_model.allow_imprecise = True

# Relocate puts
code.update_symbol_value("memset", memset_model._address)


# Create a type of exception only I will generate
class FailExitException(Exception):
    pass


# We signal failure memsets by dereferencing 0xdead.
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
machine.emulate(emulator)
