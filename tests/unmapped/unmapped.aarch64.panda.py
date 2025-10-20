import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.DEBUG)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.AARCH64, smallworld.platforms.Byteorder.LITTLE
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

# Create a stack and add it to the state
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x7FFF0000, 0x10000)
machine.add(stack)

# Configure the stack pointer
sp = stack.get_pointer()
cpu.sp.set(sp)

# Use code bounds from the ELF
for bound in code.bounds:
    machine.add_bound(bound[0], bound[1])

# Set up the first test
entrypoint = code.get_symbol_value("read_unmapped")
cpu.pc.set(entrypoint)

# Emulate
emulator = smallworld.emulators.PandaEmulator(platform)
# final_machine = machine.emulate(emulator)
idx = 0
for final_machine in machine.step(emulator):
    idx += 1
    if idx == 5:
        break

print(final_machine.get_cpu().x0)
