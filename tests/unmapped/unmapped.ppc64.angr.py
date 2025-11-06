import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.POWERPC64, smallworld.platforms.Byteorder.BIG
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

# NOTE: Entrypoints encoded manually.
#
# PowerPC's function symbols aren't direct pointers to the code,
# they're pointers to function pointer structs.
# Because IBM decided that function pointers
# needed to be 24-byte structs, not just single addresses.

# First test: read unmapped memory
try:
    entrypoint = 0x10000684
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.AngrEmulator(platform)
    emulator.enable_linear()
    emulator.error_on_unmapped = True
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory read")
except smallworld.exceptions.EmulationReadUnmappedFailure:
    pass

# Second test: write unmapped memory
try:
    entrypoint = 0x100006C4
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.AngrEmulator(platform)
    emulator.enable_linear()
    emulator.error_on_unmapped = True
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory write")
except smallworld.exceptions.EmulationWriteUnmappedFailure:
    pass

# Third test: fetch unmapped memory
try:
    entrypoint = 0x10000704
    cpu.pc.set(entrypoint)
    emulator = smallworld.emulators.AngrEmulator(platform)
    emulator.enable_linear()
    emulator.error_on_unmapped = True
    final_machine = machine.emulate(emulator)
    raise Exception("Did not report an unmapped memory fetch")
except smallworld.exceptions.EmulationReadUnmappedFailure:
    # Yes, you read this right.
    #
    # Thanks to the whole "function pointers are structs" thing,
    # calling a bad function pointer will give you a read error
    # before it gives a fetch error.
    #
    # I could probably do some megahacks to mimic
    # an actual fetch failure, but I think this is going
    # to be a more realistic case.
    pass
