import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

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

# Load and add code from lib.
# Pray to pudding that

# Set entrypoint from the ELF
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Define a fake exit point for test 1
exitpoint = 0x10101010

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

stack.push_integer(exitpoint, 8, None)

cpu.sp.set(stack.get_pointer())
cpu.lr.set(exitpoint)

# Use code bounds from the ELF
machine.add_exit_point(exitpoint)
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

# Test 1: Return to unmapped exit point
emulator = smallworld.emulators.UnicornEmulator(platform)
final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()

if final_cpu.pc.get() != exitpoint:
    raise ValueError(f"Expected PC to be {hex(exitpoint)}, got {final_cpu.pc}")
if final_cpu.r0.get() != 42:
    raise ValueError(f"Expected r0 to be 0x2a, got {final_cpu.r0}")
print("Test 1 SUCCESS")

# Test 2: Exit point in middle of code
exitpoint = entrypoint + code.get_symbol_size("main") - 12
machine.add_exit_point(exitpoint)

emulator = smallworld.emulators.UnicornEmulator(platform)
final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()

if final_cpu.pc.get() != exitpoint:
    raise ValueError(f"Expected PC to be {hex(exitpoint)}, got {final_cpu.pc}")
if final_cpu.r0.get() != 42:
    raise ValueError(f"Expected r0 to be 0x2a, got {final_cpu.r0}")
print("Test 2 SUCCESS")
