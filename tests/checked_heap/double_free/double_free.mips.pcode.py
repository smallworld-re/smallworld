import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.MIPS32, smallworld.platforms.Byteorder.BIG
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
heap = smallworld.state.memory.heap.CheckedBumpAllocator(0x20000, 0x1000, 16)
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

# Emulate
emulator = smallworld.emulators.GhidraEmulator(platform)
if isinstance(emulator, smallworld.emulators.AngrEmulator):
    emulator.enable_linear()

emulator.add_exit_point(entrypoint + 0x1000)
try:
    machine.emulate(emulator)
    raise Exception("Did not exit as expected")
except ValueError as e:
    assert str(e).startswith("Invalid Free at ")
