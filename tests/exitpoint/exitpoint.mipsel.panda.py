import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)

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
    code = smallworld.state.memory.code.Executable.from_elf(f, platform=platform)
    machine.add(code)

# Load and add code from lib.
# Pray to pudding that

# Set entrypoint from the ELF
entrypoint = code.get_symbol_value("main")
cpu.pc.set(entrypoint)

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

stack.push_integer(0x10101010, 8, None)

cpu.sp.set(stack.get_pointer())
cpu.ra.set(0x10101010)

# Use code bounds from the ELF
machine.add_exit_point(0x10101010)
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

emulator = smallworld.emulators.PandaEmulator(platform)
final_machine = machine.emulate(emulator)
final_cpu = final_machine.get_cpu()

print(final_cpu.pc)
print(final_cpu.v0)
