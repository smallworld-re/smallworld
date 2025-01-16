import logging

import smallworld

# Set up logging and hinting
smallworld.logging.setup_logging(level=logging.INFO)
smallworld.hinting.setup_hinting(stream=True, verbose=True)

# Define the platform
platform = smallworld.platforms.Platform(
    smallworld.platforms.Architecture.RISCV64, smallworld.platforms.Byteorder.LITTLE
)

# Create a machine
machine = smallworld.state.Machine()

# create a CPU
cpu = smallworld.state.cpus.CPU.for_platform(platform)
machine.add(cpu)

# load and add code into the state
code = smallworld.state.memory.code.Executable.from_filepath(
    __file__.replace(".py", ".bin").replace(".angr", ""), address=0x1000
)
machine.add(code)

# Create and register a stack
stack = smallworld.state.memory.stack.Stack.for_platform(platform, 0x2000, 0x4000)
machine.add(stack)

# Set the instruction pointer to the code entrypoint
cpu.pc.set(code.address)

# Initialize argument registers
cpu.a0.set(0x11111111)
cpu.a1.set(0x01010101)
cpu.a2.set(0x22222222)
cpu.a3.set(0x01010101)
cpu.a4.set(0x33333333)
cpu.a5.set(0x01010101)
cpu.a6.set(0x44444444)
cpu.a7.set(0x01010101)

# Push a value onto the stack, and configure the stack pointer
stack.push_integer(0x55555555, 8, None)
sp = stack.get_pointer()
cpu.sp.set(sp)

# emulate
emulator = smallworld.emulators.AngrEmulator(platform)
emulator.enable_linear()
emulator.add_exit_point(cpu.pc.get() + code.get_capacity())
final_machine = machine.emulate(emulator)

# read out the final state
final_cpu = final_machine.get_cpu()
print(final_cpu.a0)
