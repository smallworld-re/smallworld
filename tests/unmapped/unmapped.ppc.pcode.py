import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC32, smallworld.platforms.Byteorder.BIG
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

# NOTE: We purposefully don't add bounds.

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# May I say I hate ABIs that use data above the stack pointer?
stack.push_bytes(b"\0" * 32, None)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# First test: read unmapped memory
try:
    entrypoint = code.get_symbol_value("read_unmapped")
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.GhidraEmulator(platform)
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory read")
except smallworld.exceptions.EmulationReadUnmappedFailure:
    pass

# Second test: write unmapped memory
try:
    entrypoint = code.get_symbol_value("write_unmapped")
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.GhidraEmulator(platform)
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory write")
except smallworld.exceptions.EmulationWriteUnmappedFailure:
    pass

# Third test: fetch unmapped memory
try:
    entrypoint = code.get_symbol_value("fetch_unmapped")
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.GhidraEmulator(platform)
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory fetch")
except smallworld.exceptions.EmulationFetchUnmappedFailure:
    pass
