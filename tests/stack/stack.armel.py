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

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin")
    .replace(".angr", "")
    .replace(".panda", "")
    .replace(".ghidra", ""),
    address=0x1000,
)
machine.add(code)

# Create and register a stack
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the machine entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
cpu.r0.set(0x11111111)
cpu.r1.set(0x01010101)
cpu.r2.set(0x22222222)
cpu.r3.set(0x01010101)

# Push additional arguments onto the stack, and configure the stack pointer
stack.push_integer(0x44444444, 4, None)
stack.push_integer(0x01010101, 4, None)
stack.push_integer(0x33333333, 4, None)

sp = stack.get_pointer()
cpu.sp.set(sp)

# emulate
emulator = smallworld.emulators.UnicornEmulator(platform)
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(final_cpu.r0)
